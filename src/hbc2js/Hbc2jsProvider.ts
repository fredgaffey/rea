import { analysisClientFailureForOperation } from "../providers/AnalysisClientFailure.js";
import { ownedProcessPrerequisiteAvailability } from "../providers/ownedProcessAvailability.js";
import { HOST_PLATFORM } from "../platform/HostPlatform.js";
import { snapshotEnvironment } from "../process/snapshotEnvironment.js";
import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
  type ProviderAvailability,
} from "../ports/AnalysisProvider.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisProtocolError,
  cancelledBy,
  OwnerCancellation,
} from "../domain/analysisErrorCore.js";
import { providerConfigurationRefusal } from "../domain/providerConfigurationRefusal.js";
import { err, ok, type Result } from "../domain/result.js";
import type { Hbc2jsRequest } from "../domain/hbc2js/hermesBytecode.js";
import type { AnalysisSettingsReader } from "../domain/analysisSettings.js";
import { selectedAnalysisSetting } from "../domain/analysisSettingDefinitions.js";
import { DEFAULT_HBC2JS_DECOMPILE_TIMEOUT_MS } from "../domain/analysisResourceLimits.js";
import { ArtifactResourceScope } from "../resources/index.js";
import type { Hbc2jsCommandSelection } from "./Hbc2jsConfiguration.js";
import {
  Hbc2jsConfigurationFailure,
  hbc2jsConfigurationAvailability,
  resolveHbc2jsCommand,
} from "./Hbc2jsConfiguration.js";
import { HBC2JS_PROVIDER_IDENTITY } from "./Hbc2jsProviderIdentity.js";
import { inspectHermesBytecode } from "./Hbc2jsBytecodeInspection.js";
import { decompileHermesFunction } from "./Hbc2jsFunctionDecompilation.js";
import { inspectHbc2jsClient } from "./Hbc2jsVersionProbe.js";

const INSPECT_CLIENT = "inspect_hbc2js_client";

const throwIfCancelled = (
  operation: string,
  signal: AbortSignal | undefined,
): void => {
  if (signal?.aborted === true) throw cancelledBy(operation, signal);
};

export interface Hbc2jsProviderOptions {
  /** Environment that selects the launcher; defaults to the process environment. */
  readonly environment?: Readonly<Record<string, string | undefined>>;
  /** The host hbc2js runs on; defaults to the running host. */
  readonly platform?: NodeJS.Platform;
  /** Runtime analysis settings (hbc2js.decompile_timeout_ms, hbc2js.max_heap_mb). */
  readonly settings?: AnalysisSettingsReader;
}

/**
 * Hermes bytecode analysis over a caller-selected hbc2js launcher. Every
 * operation is a static read: the only effect is launching the hbc2js process.
 */
export class Hbc2jsProvider {
  private readonly platform: NodeJS.Platform;
  private readonly selectedEnvironment:
    | Readonly<Record<string, string | undefined>>
    | undefined;

  readonly #artifacts = new ArtifactResourceScope();
  readonly #shutdown = new AbortController();
  readonly #active = new Set<Promise<void>>();
  #closing = false;
  #closePromise: Promise<void> | undefined;

  readonly #settings: AnalysisSettingsReader | undefined;

  constructor(options: Hbc2jsProviderOptions = {}) {
    this.#settings = options.settings;
    this.platform = options.platform ?? HOST_PLATFORM.platform;
    this.selectedEnvironment =
      options.environment === undefined
        ? undefined
        : snapshotEnvironment(options.environment, this.platform);
  }

  private operationEnvironment(): Readonly<NodeJS.ProcessEnv> {
    return (
      this.selectedEnvironment ??
      snapshotEnvironment(process.env, this.platform)
    );
  }

  /** Probe the selected hbc2js launcher; reads no target. */
  inspectAvailability(signal?: AbortSignal): Promise<ProviderAvailability> {
    if (this.#closing)
      return Promise.reject(
        cancelledBy(INSPECT_CLIENT, OwnerCancellation.ownerClosed),
      );
    const operationSignal =
      signal === undefined
        ? this.#shutdown.signal
        : AbortSignal.any([signal, this.#shutdown.signal]);
    return this.#track(
      this.#artifacts
        .run(() => this.#inspectAvailability(operationSignal))
        .catch((cause: unknown) => {
          throw analysisClientFailureForOperation(
            cause,
            HBC2JS_PROVIDER_IDENTITY.id,
            INSPECT_CLIENT,
          );
        }),
    );
  }

  async #inspectAvailability(
    signal: AbortSignal,
  ): Promise<ProviderAvailability> {
    const environment = this.operationEnvironment();
    try {
      const selection = await resolveHbc2jsCommand(
        environment,
        this.platform,
        signal,
      );
      await inspectHbc2jsClient(selection, this.#artifacts, {
        signal,
        environment,
        platform: this.platform,
      });
      throwIfCancelled(INSPECT_CLIENT, signal);
      return {
        status: "available",
        code: null,
        reason: null,
        diagnostics: {
          selected_command: selection.command,
          command_source: selection.commandSource,
        },
      };
    } catch (cause) {
      if (cause instanceof Hbc2jsConfigurationFailure)
        return hbc2jsConfigurationAvailability(cause);
      const prerequisite = ownedProcessPrerequisiteAvailability(cause);
      if (prerequisite !== undefined) return prerequisite;
      throw cause;
    }
  }

  execute(
    request: Hbc2jsRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    if (this.#closing)
      return Promise.resolve(
        err(cancelledBy(request.operation, OwnerCancellation.ownerClosed)),
      );
    const signal =
      options?.signal === undefined
        ? this.#shutdown.signal
        : AbortSignal.any([options.signal, this.#shutdown.signal]);
    return this.#track(
      this.#artifacts
        .run(() => this.#execute(request, signal))
        .catch((cause: unknown) =>
          err(
            analysisClientFailureForOperation(
              cause,
              HBC2JS_PROVIDER_IDENTITY.id,
              request.operation,
            ),
          ),
        ),
    );
  }

  async #execute(
    request: Hbc2jsRequest,
    signal: AbortSignal,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    if (signal.aborted) return err(cancelledBy(request.operation, signal));
    const environment = this.operationEnvironment();
    try {
      const selection = await resolveHbc2jsCommand(
        environment,
        this.platform,
        signal,
      );
      const versionOutputLimit = request.input.version_output_limit_bytes;
      const identity = await inspectHbc2jsClient(selection, this.#artifacts, {
        signal,
        environment,
        platform: this.platform,
        ...(versionOutputLimit === undefined
          ? {}
          : { versionOutputLimitBytes: versionOutputLimit }),
      });
      if (signal.aborted) return err(cancelledBy(request.operation, signal));
      if (request.operation === "inspect_hermes_bytecode") {
        const inspected = await inspectHermesBytecode(
          request,
          selection,
          this.#artifacts,
          { signal, environment, platform: this.platform },
        );
        if (signal.aborted) return err(cancelledBy(request.operation, signal));
        return ok(
          createAnalysisExecution(
            inspected.result,
            {
              ...HBC2JS_PROVIDER_IDENTITY,
              version: `hbc2js@${identity.version}`,
            },
            {
              limitations: [...identity.limitations, ...inspected.limitations],
            },
          ),
        );
      }
      if (request.operation === "decompile_hermes_function")
        return this.#decompile(request, selection, identity.version, {
          signal,
          environment,
          identityLimitations: identity.limitations,
        });
      return ok(
        createAnalysisExecution(
          {
            client: {
              command: selection.command,
              command_source: selection.commandSource,
              hbc2js_version: identity.version,
              contract: identity.contract,
              hbc_versions: [...identity.hbcVersions],
              node: identity.node,
              admission: identity.admission,
            },
          },
          {
            ...HBC2JS_PROVIDER_IDENTITY,
            version: `hbc2js@${identity.version}`,
          },
          { limitations: identity.limitations },
        ),
      );
    } catch (cause) {
      if (cause instanceof AnalysisError)
        return err(
          analysisClientFailureForOperation(
            cause,
            HBC2JS_PROVIDER_IDENTITY.id,
            request.operation,
          ),
        );
      if (cause instanceof Hbc2jsConfigurationFailure)
        return err(
          providerConfigurationRefusal(
            HBC2JS_PROVIDER_IDENTITY.id,
            request.operation,
            cause,
          ),
        );
      return err(
        new AnalysisProtocolError(
          `hbc2js version probe failed for ${request.operation}`,
          { cause },
        ),
      );
    }
  }

  async #decompile(
    request: Extract<Hbc2jsRequest, { operation: "decompile_hermes_function" }>,
    selection: Hbc2jsCommandSelection,
    version: string,
    run: {
      readonly signal: AbortSignal;
      readonly environment: Readonly<NodeJS.ProcessEnv>;
      readonly identityLimitations: readonly string[];
    },
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const { signal, environment } = run;
    const overrides = this.#settings?.().overrides;
    const timeout = selectedAnalysisSetting(
      request.input.decompile_timeout_ms,
      overrides?.["hbc2js.decompile_timeout_ms"],
      DEFAULT_HBC2JS_DECOMPILE_TIMEOUT_MS,
    );
    const decompiled = await decompileHermesFunction(request, {
      selection,
      scope: this.#artifacts,
      limits: {
        timeoutMs: timeout.value,
        heapMb:
          request.input.max_heap_mb ??
          overrides?.["hbc2js.max_heap_mb"] ??
          null,
        timeoutSource: timeout.source,
      },
      signal,
      environment,
      platform: this.platform,
    });
    if (signal.aborted) return err(cancelledBy(request.operation, signal));
    return ok(
      createAnalysisExecution(
        decompiled.result,
        { ...HBC2JS_PROVIDER_IDENTITY, version: `hbc2js@${version}` },
        {
          limitations: [...run.identityLimitations, ...decompiled.limitations],
        },
      ),
    );
  }

  #track<T>(operation: Promise<T>): Promise<T> {
    const settled = operation.then(
      () => undefined,
      () => undefined,
    );
    this.#active.add(settled);
    void settled.then(() => this.#active.delete(settled));
    return operation;
  }

  /** Retain failed cleanup ownership and retry it on close. */
  async close(): Promise<void> {
    this.#closing = true;
    this.#shutdown.abort(OwnerCancellation.ownerClosed);
    this.#closePromise ??= this.#drainAndClean().catch((cause: unknown) => {
      this.#closePromise = undefined;
      throw cause;
    });
    return this.#closePromise;
  }

  async #drainAndClean(): Promise<void> {
    await Promise.all(this.#active);
    try {
      await this.#artifacts.close();
    } catch (cause) {
      throw analysisClientFailureForOperation(
        cause,
        HBC2JS_PROVIDER_IDENTITY.id,
        "close",
      );
    }
  }
}
