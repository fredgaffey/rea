import { capturedProviderOutput } from "../process/capturedProviderOutput.js";
import { providerOutcomeOf } from "../process/ProviderOutcome.js";
import { fixedAllowanceOptions } from "../domain/fixedAllowanceRemediation.js";
import {
  classifyProviderFailure,
  type ProviderFailureDialect,
} from "../providers/classifyProviderFailure.js";
import { HBC2JS_PROVIDER_IDENTITY } from "./Hbc2jsProviderIdentity.js";
import { ok, err, type Result } from "../domain/result.js";
import { Hbc2jsCommandCleanup } from "./Hbc2jsCommandCleanup.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { launcherFailureOf } from "../process/launchFailure.js";
import { snapshotEnvironment } from "../process/snapshotEnvironment.js";

import { randomUUID } from "node:crypto";
import {
  OwnedCommandFailure,
  runOwnedCommand,
  prepareOwnedCommand,
} from "../process/OwnedCommand.js";
import { WindowsBatchCommandError } from "../process/WindowsBatchCommand.js";

import { admitHbc2jsVersion, HBC2JS_CONTRACT } from "./Hbc2jsRelease.js";
import { describeHbc2jsOutputFailure } from "./Hbc2jsFailures.js";
import {
  isHbc2jsVersionReply,
  parseHbc2jsMachineReply,
} from "./Hbc2jsOutput.js";
import {
  hbc2jsInvocation,
  Hbc2jsConfigurationFailure,
  hbc2jsVersionProbeTimeoutGuidance,
  HBC2JS_COMMAND_ENV,
  HBC2JS_MISSING_REMEDIATION,
  HBC2JS_NOT_EXECUTABLE_REMEDIATION,
  HBC2JS_VERSION_REMEDIATION,
  VERSION_MAX_OUTPUT_BYTES,
  VERSION_TIMEOUT_MS,
  type Hbc2jsCommandSelection,
  type Hbc2jsInvocation,
} from "./Hbc2jsConfiguration.js";

/** What the version probe admitted about the selected launcher. */
export interface Hbc2jsClientIdentity {
  readonly version: string;
  readonly contract: number;
  readonly hbcVersions: readonly number[];
  readonly node: string;
  readonly admission: "verified" | "compatible";
  readonly limitations: readonly string[];
}

/** Probe within the caller-admitted command scope; decodes nothing. */
export const inspectHbc2jsClient = async (
  selection: Hbc2jsCommandSelection,
  cleanup: Hbc2jsCommandCleanup,
  options: {
    readonly signal?: AbortSignal;
    readonly environment?: Readonly<Record<string, string | undefined>>;
    readonly platform: NodeJS.Platform;
  },
): Promise<Hbc2jsClientIdentity> => {
  const { signal, environment = process.env, platform } = options;
  const hostEnvironment = snapshotEnvironment(environment, platform);
  let invocation: Hbc2jsInvocation;
  try {
    invocation = hbc2jsInvocation(
      selection,
      ["--version", "--json"],
      hostEnvironment,
      platform,
    );
  } catch (cause) {
    if (!(cause instanceof WindowsBatchCommandError)) throw cause;
    throw new Hbc2jsConfigurationFailure(
      "launcher_unsupported",
      `The selected hbc2js launcher cannot be run through cmd.exe: ${cause.message}`,
      `Set ${HBC2JS_COMMAND_ENV} to a launcher path without cmd.exe metacharacters (" % ^ ! & | < >), or to a native hbc2js executable.`,
      {
        selected_command: selection.command,
        command_source: selection.commandSource,
      },
      { cause },
    );
  }
  let interpreted:
    | Result<Hbc2jsClientIdentity, Hbc2jsConfigurationFailure>
    | undefined;
  try {
    // The owned process group stops a shell launcher's children with it; a
    // child holding inherited output pipes cannot outlive the deadline.
    await prepareOwnedCommand(signal);
    await runOwnedCommand(
      {
        command: invocation.command,
        arguments: invocation.arguments,
        windowsVerbatimArguments: invocation.windowsVerbatimArguments,
        // Hbc2js launchers are commonly interpreter scripts, so ownership is
        // proved by the run token rather than the launcher's argv prefix.
        expectedCommand: null,
        runId: randomUUID(),
        hostEnvironment,
      },
      {
        timeoutMs: VERSION_TIMEOUT_MS,
        diagnosticBytes: VERSION_MAX_OUTPUT_BYTES,
        observeCompleted: (snapshot) => {
          try {
            interpreted = ok(
              interpretHbc2jsVersion(
                snapshot.stdout.text,
                snapshot.stderr.text,
                selection,
              ),
            );
          } catch (cause) {
            if (!(cause instanceof Hbc2jsConfigurationFailure)) throw cause;
            interpreted = err(cause);
          }
        },
      },
      signal === undefined ? {} : { signal },
    );
  } catch (cause) {
    const recordedFailure =
      interpreted?.ok === false ? interpreted.error : undefined;
    const cancellation =
      cause instanceof OwnedCommandFailure ? cause.cancellation : undefined;
    const failure =
      recordedFailure === undefined
        ? (launcherConfigurationFailure(cause, selection) ??
          classifyProviderFailure(cause, hbc2jsProbeDialect(selection)))
        : new Hbc2jsConfigurationFailure(
            recordedFailure.code,
            recordedFailure.message,
            recordedFailure.remediation,
            {
              ...recordedFailure.diagnostics,
              ...(cancellation === undefined
                ? {}
                : { cancellation_observed: true }),
            },
            { cause },
          );
    const primary =
      failure instanceof AnalysisError
        ? failure
        : new ProviderAdapterError("hbc2js", "inspect_hbc2js_client", {
            cause: failure,
            userMessage: failure.message,
            diagnostics: failure.diagnostics,
          });
    const retained = cleanup.retainFailure({
      cause,
      primary,
      operation: "inspect_hbc2js_client",
    });
    throw retained === primary ? failure : retained;
  }
  if (interpreted === undefined)
    throw new Hbc2jsConfigurationFailure(
      "version_unresolved",
      "The owned version command completed without an output observation",
      HBC2JS_VERSION_REMEDIATION,
      { selected_command: selection.command },
    );
  if (!interpreted.ok) throw interpreted.error;
  return interpreted.value;
};

const interpretHbc2jsVersion = (
  stdout: string,
  stderr: string,
  selection: Hbc2jsCommandSelection,
): Hbc2jsClientIdentity => {
  const diagnostics = {
    selected_command: selection.command,
    command_source: selection.commandSource,
  };
  const parsed = parseHbc2jsMachineReply(stdout);
  if (!parsed.ok) {
    const unsupported = parsed.error.kind === "schema_tag";
    throw new Hbc2jsConfigurationFailure(
      unsupported ? "unsupported_version" : "version_unresolved",
      unsupported
        ? `The selected hbc2js launcher speaks an unsupported machine schema: ${describeHbc2jsOutputFailure(parsed.error)}`
        : `The selected hbc2js launcher did not return a usable --version --json reply: ${describeHbc2jsOutputFailure(parsed.error)}`,
      unsupported
        ? `Use an hbc2js release that supports contract ${String(HBC2JS_CONTRACT)}; see docs/guides/android/hermes-bytecode-analysis.md.`
        : HBC2JS_VERSION_REMEDIATION,
      {
        ...diagnostics,
        version_probe: parsed.error.kind,
        stdout,
        stderr,
      },
    );
  }
  const reply = parsed.value;
  if (!isHbc2jsVersionReply(reply))
    throw new Hbc2jsConfigurationFailure(
      "version_unresolved",
      `The selected hbc2js launcher answered --version --json with a ${reply.kind} reply`,
      HBC2JS_VERSION_REMEDIATION,
      { ...diagnostics, reply_kind: reply.kind },
    );
  const admission = admitHbc2jsVersion(reply);
  if (admission.status === "unsupported")
    throw new Hbc2jsConfigurationFailure(
      "unsupported_version",
      admission.message,
      `Use an hbc2js release that reports contract ${String(HBC2JS_CONTRACT)}; see docs/guides/android/hermes-bytecode-analysis.md.`,
      {
        ...diagnostics,
        reported_version: reply.hbc2js,
        reported_contract: reply.contract,
        required_contract: HBC2JS_CONTRACT,
      },
    );
  return {
    version: admission.version,
    contract: reply.contract,
    hbcVersions: reply.hbcVersions,
    node: reply.node,
    admission: admission.status,
    limitations:
      admission.status === "compatible" ? [admission.limitation] : [],
  };
};

/**
 * The failures only the selected launcher can cause: it is missing, not
 * executable, or ran and exited without a usable version. Everything else is
 * the shared classifier's.
 */
const launcherConfigurationFailure = (
  cause: unknown,
  selection: Hbc2jsCommandSelection,
): Hbc2jsConfigurationFailure | undefined => {
  const launch = launcherFailureOf(cause);
  const diagnostics = {
    selected_command: selection.command,
    command_source: selection.commandSource,
  };
  if (launch?.kind === "missing" || launch?.kind === "not_executable") {
    const execDenied = launch.kind === "not_executable";
    return new Hbc2jsConfigurationFailure(
      execDenied ? "command_not_executable" : "command_missing",
      execDenied
        ? `Execution of the selected hbc2js launcher was denied: ${selection.command}`
        : `The selected hbc2js launcher was not found: ${selection.command}`,
      execDenied
        ? HBC2JS_NOT_EXECUTABLE_REMEDIATION
        : HBC2JS_MISSING_REMEDIATION,
      { filesystem_error: launch.code, ...diagnostics },
      { cause },
    );
  }
  const kind = providerOutcomeOf(cause)?.kind;
  if (kind !== "exited" && kind !== "protocol") return undefined;
  const snapshot = cause instanceof OwnedCommandFailure ? cause.snapshot : null;
  return new Hbc2jsConfigurationFailure(
    "version_unresolved",
    "The selected hbc2js launcher did not report a usable version",
    HBC2JS_VERSION_REMEDIATION,
    {
      selected_command: selection.command,
      ...(snapshot === null
        ? {}
        : {
            exit_code: snapshot.exitCode ?? null,
            stderr_excerpt: snapshot.stderr.text.slice(0, 512),
          }),
    },
    { cause },
  );
};

/** How the shared classifier reports the version probe's remaining failures. */
const hbc2jsProbeDialect = (
  selection: Hbc2jsCommandSelection,
): ProviderFailureDialect => {
  const diagnostics = {
    selected_command: selection.command,
    command_source: selection.commandSource,
  };
  return {
    providerId: HBC2JS_PROVIDER_IDENTITY.id,
    operation: "inspect_hbc2js_client",
    command: () => ({
      operation: "inspect_hbc2js_client",
      capturedOutput: capturedProviderOutput,
      timeout: {
        ms: VERSION_TIMEOUT_MS,
        ...hbc2jsVersionProbeTimeoutGuidance(),
      },
      outputLimit: {
        limits: { max_output_bytes: VERSION_MAX_OUTPUT_BYTES },
        recovery: fixedAllowanceOptions(
          "The hbc2js version-output capture allowance (decompile_timeout_ms does not raise it)",
          "capture",
          { limit: VERSION_MAX_OUTPUT_BYTES, unit: "bytes" },
        ),
      },
      dialect: (_exit, _details, unclassified) => unclassified({ diagnostics }),
    }),
    unclassified: (cause, details) =>
      new ProviderAdapterError(
        HBC2JS_PROVIDER_IDENTITY.id,
        "inspect_hbc2js_client",
        { ...details, cause, diagnostics },
      ),
  };
};
