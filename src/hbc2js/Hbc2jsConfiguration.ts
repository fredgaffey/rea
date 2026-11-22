import {
  AnalysisTimeoutError,
  cancelledBy,
  carriedReason,
} from "../domain/analysisErrorCore.js";
import { isQualifiedCallerPath } from "../filesystem/callerPath.js";
import { snapshotEnvironment } from "../process/snapshotEnvironment.js";
import { findWindowsExecutable } from "../process/WindowsExecutable.js";
import { ProviderStartupDeadline } from "../process/ProviderDeadline.js";

import type { ProviderAvailability } from "../ports/AnalysisProvider.js";
import type { ProviderRejectionCode } from "../domain/providerSelection.js";
import type { JsonValue } from "../domain/jsonValue.js";
import {
  isWindowsBatchFile,
  windowsBatchCommand,
} from "../process/WindowsBatchCommand.js";

/** Environment key selecting the caller's hbc2js launcher. */
export const HBC2JS_COMMAND_ENV = "REA_HBC2JS_COMMAND";

export const VERSION_TIMEOUT_MS = 20_000;
export const VERSION_MAX_OUTPUT_BYTES = 64 * 1024;

export const hbc2jsVersionProbeTimeoutGuidance = (): {
  readonly userMessage: string;
  readonly remediationAction: string;
} => ({
  userMessage: `hbc2js version probe reached its ${String(VERSION_TIMEOUT_MS)} ms deadline (deadlineExpired). This release has no runtime override.`,
  remediationAction: `This ${String(VERSION_TIMEOUT_MS)} ms hbc2js version probe has no runtime override. decompile_timeout_ms does not raise it. Allow execution, cleanup and delivery headroom in the outer MCP client deadline. Confirm outstanding work and cleanup before retrying.`,
});

export const HBC2JS_VERSION_REMEDIATION = `Set ${HBC2JS_COMMAND_ENV} to an hbc2js launcher whose --version --json reply reports contract 1, or put one on PATH.`;
/** Repair when the selected hbc2js launcher does not exist. */
export const HBC2JS_MISSING_REMEDIATION = `Set ${HBC2JS_COMMAND_ENV} to the absolute path of the hbc2js launcher (the installed hbc2js command), or put hbc2js on PATH.`;
/** Repair when execution of the selected hbc2js launcher is denied. */
export const HBC2JS_NOT_EXECUTABLE_REMEDIATION = `Check file type and execute permission for ${HBC2JS_COMMAND_ENV} or select an executable hbc2js launcher.`;

/** How the hbc2js launcher was selected for this provider instance. */
export interface Hbc2jsCommandSelection {
  readonly command: string;
  readonly commandSource: "environment" | "path";
}

/**
 * Preserve an explicit launcher, or resolve the default Windows command before
 * choosing native versus batch process creation. POSIX keeps execFile's PATH
 * lookup. The resolved selection is reused for the version and decode runs.
 */
export const resolveHbc2jsCommand = async (
  environment: Readonly<Record<string, string | undefined>>,
  platform: NodeJS.Platform,
  signal?: AbortSignal,
): Promise<Hbc2jsCommandSelection> => {
  if (signal?.aborted === true)
    throw cancelledBy("inspect_hbc2js_client", signal);
  const selectedEnvironment = snapshotEnvironment(environment, platform);
  const configured = selectedEnvironment[HBC2JS_COMMAND_ENV];
  if (configured !== undefined && configured.trim() !== "") {
    if (!isQualifiedCallerPath(configured, platform))
      throw new Hbc2jsConfigurationFailure(
        "not_absolute",
        `${HBC2JS_COMMAND_ENV} must be an absolute path to the hbc2js launcher`,
        `Set ${HBC2JS_COMMAND_ENV} to an absolute hbc2js launcher path, or unset it to use hbc2js from PATH.`,
        { configured_command: configured },
      );
    return { command: configured, commandSource: "environment" };
  }
  if (platform !== "win32") return { command: "hbc2js", commandSource: "path" };
  // A single deadline owns the whole PATH search, including filesystem waits.
  const deadline = new ProviderStartupDeadline(VERSION_TIMEOUT_MS, signal);
  const lookupInterruption = () =>
    deadline.interruption === "cancelled"
      ? cancelledBy("inspect_hbc2js_client", carriedReason(signal?.reason))
      : new AnalysisTimeoutError("inspect_hbc2js_client", VERSION_TIMEOUT_MS, {
          diagnostics: { phase: "windows_path_lookup" },
          ...hbc2jsVersionProbeTimeoutGuidance(),
        });
  try {
    const found = await findWindowsExecutable("hbc2js", selectedEnvironment, {
      signal: deadline.signal,
      allowBatch: true,
    });
    if (found.ok) return { command: found.value, commandSource: "path" };
    const failure = found.error;
    if (failure.kind === "interrupted") throw lookupInterruption();
    if (failure.kind === "invalid_extension")
      throw new Hbc2jsConfigurationFailure(
        "command_unresolved",
        "Windows PATHEXT must contain filename extensions, not paths",
        `Correct PATHEXT so it lists filename extensions only, or set ${HBC2JS_COMMAND_ENV} to an absolute hbc2js launcher.`,
        {
          selected_command: "hbc2js",
          command_source: "path",
          invalid_extension: failure.extension,
        },
      );
    if (failure.kind === "inspection")
      throw new Hbc2jsConfigurationFailure(
        "command_unresolved",
        `The PATH-selected hbc2js launcher could not be inspected: ${failure.path}`,
        `Make the PATH-selected hbc2js launcher readable, or set ${HBC2JS_COMMAND_ENV} to an absolute hbc2js launcher.`,
        {
          selected_command: "hbc2js",
          command_source: "path",
          candidate_path: failure.path,
          ...(failure.code === null ? {} : { filesystem_error: failure.code }),
        },
        { cause: failure.cause },
      );
  } finally {
    deadline.dispose();
  }

  throw new Hbc2jsConfigurationFailure(
    "command_missing",
    "The hbc2js launcher was not found on the selected Windows PATH/PATHEXT",
    `Set ${HBC2JS_COMMAND_ENV} to an absolute hbc2js launcher, or add its directory and extension to PATH and PATHEXT.`,
    {
      selected_command: "hbc2js",
      command_source: "path",
    },
  );
};

export type Hbc2jsConfigurationFailureCode =
  | "not_absolute"
  | "command_missing"
  | "command_not_executable"
  | "command_unresolved"
  | "launcher_unsupported"
  | "version_unresolved"
  | "unsupported_version";

/** Why the selected hbc2js launcher is unusable, with the owner's repair instruction. */
export class Hbc2jsConfigurationFailure extends Error {
  constructor(
    readonly code: Hbc2jsConfigurationFailureCode,
    message: string,
    readonly remediation: string,
    readonly diagnostics: Readonly<Record<string, JsonValue>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
  }
}

/** Process creation for one hbc2js run on the selected host. */
export interface Hbc2jsInvocation {
  readonly command: string;
  readonly arguments: readonly string[];
  readonly windowsVerbatimArguments: boolean;
}

/**
 * Run the selected launcher directly, or through cmd.exe when Windows can
 * only execute it there (the Chocolatey `hbc2js.bat` and `java -jar`
 * wrapper scripts). Throws WindowsBatchCommandError when a token cannot be
 * passed to cmd.exe safely.
 */
export const hbc2jsInvocation = (
  selection: Hbc2jsCommandSelection,
  arguments_: readonly string[],
  environment: Readonly<NodeJS.ProcessEnv>,
  platform: NodeJS.Platform,
): Hbc2jsInvocation =>
  platform === "win32" && isWindowsBatchFile(selection.command)
    ? {
        ...windowsBatchCommand({
          environment,
          batchPath: selection.command,
          arguments: arguments_,
        }),
        windowsVerbatimArguments: true,
      }
    : {
        command: selection.command,
        arguments: arguments_,
        windowsVerbatimArguments: false,
      };

/** Availability in the shape shared by every provider. */
const rejectionCodeOf = (
  code: Hbc2jsConfigurationFailureCode,
): ProviderRejectionCode =>
  code === "command_missing"
    ? "executable_missing"
    : code === "command_not_executable" ||
        code === "not_absolute" ||
        code === "launcher_unsupported" ||
        code === "command_unresolved"
      ? "not_configured"
      : code === "unsupported_version"
        ? "unsupported_version"
        : "version_unresolved";

export const hbc2jsConfigurationAvailability = (
  cause: Hbc2jsConfigurationFailure,
): ProviderAvailability => ({
  status: "unavailable",
  code: rejectionCodeOf(cause.code),
  reason: cause.message,
  remediation: cause.remediation,
  diagnostics: { ...cause.diagnostics },
});

/** Fixed allowances for one decoding command; they have no runtime override. */
export const DECODE_TIMEOUT_MS = 120_000;
export const DECODE_MAX_OUTPUT_BYTES = 8 * 1024 * 1024;
