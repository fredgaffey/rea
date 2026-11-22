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
import { ArtifactResourceScope } from "../resources/index.js";
import {
  Hbc2jsConfigurationFailure,
  hbc2jsConfigurationAvailability,
  resolveHbc2jsCommand,
} from "./Hbc2jsConfiguration.js";
import { HBC2JS_PROVIDER_IDENTITY } from "./Hbc2jsProviderIdentity.js";
import { inspectHermesBytecode } from "./Hbc2jsBytecodeInspection.js";
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

  constructor(options: Hbc2jsProviderOptions = {}) {
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
      const identity = await inspectHbc2jsClient(selection, this.#artifacts, {
        signal,
        environment,
        platform: this.platform,
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
