import { randomUUID } from "node:crypto";

import { AnalysisError } from "../domain/analysisErrorBase.js";
import { analysisErrorWithCleanupDependencies } from "../domain/analysisErrorCleanup.js";
import { analysisSettingLimit } from "../domain/analysisSettingDefinitions.js";
import {
  DEFAULT_HBC2JS_DECOMPILE_TIMEOUT_MS,
  MAX_NODE_TIMER_DELAY_MS,
} from "../domain/analysisResourceLimits.js";
import {
  HBC2JS_OUTPUT_LIMITS,
  hbc2jsOutputLimitRecovery,
  hbc2jsOutputParameterLimit,
} from "../domain/hbc2js/hermesBytecode.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import type { Result } from "../domain/result.js";
import { capturedProviderOutput } from "../process/capturedProviderOutput.js";
import {
  prepareOwnedCommand,
  runOwnedCommand,
} from "../process/OwnedCommand.js";
import { snapshotEnvironment } from "../process/snapshotEnvironment.js";
import { retainOwnedCommandCleanup } from "../providers/OwnedCommandCleanup.js";
import { classifyProviderFailure } from "../providers/classifyProviderFailure.js";
import type { ArtifactResourceScope } from "../resources/index.js";
import {
  DECODE_TIMEOUT_MS,
  hbc2jsInvocation,
  type Hbc2jsCommandSelection,
} from "./Hbc2jsConfiguration.js";
import {
  describeHbc2jsOutputFailure,
  type Hbc2jsOutputFailure,
} from "./Hbc2jsFailures.js";
import {
  parseHbc2jsMachineReply,
  type Hbc2jsMachineReply,
} from "./Hbc2jsOutput.js";
import { HBC2JS_PROVIDER_IDENTITY } from "./Hbc2jsProviderIdentity.js";
import { retainedScope } from "./Hbc2jsVersionProbe.js";

/** Per-call limits for one hbc2js command; omitted means the fixed decode allowance. */
export interface Hbc2jsRunLimits {
  readonly timeoutMs: number;
  /** Passed to the child as NODE_OPTIONS=--max-old-space-size; null leaves Node's default. */
  readonly heapMb: number | null;
  readonly timeoutSource: "default" | "runtime" | "request";
}

const FIXED_LIMITS: Hbc2jsRunLimits = {
  timeoutMs: DECODE_TIMEOUT_MS,
  heapMb: null,
  timeoutSource: "default",
};

const decompileTimeoutGuidance = (limits: Hbc2jsRunLimits) => ({
  limit: analysisSettingLimit(
    "hbc2js.decompile_timeout_ms",
    limits.timeoutMs,
    limits.timeoutSource,
  ),
  ms: limits.timeoutMs,
  userMessage: `hbc2js decompile reached its ${String(limits.timeoutMs)} ms deadline (deadlineExpired).`,
  remediationAction: `Raise decompile_timeout_ms above ${String(limits.timeoutMs)} (setting hbc2js.decompile_timeout_ms, integer milliseconds from 1 to ${String(MAX_NODE_TIMER_DELAY_MS)}; omitted means ${String(DEFAULT_HBC2JS_DECOMPILE_TIMEOUT_MS)}). A running MCP server can change it with update_analysis_settings. Allow cleanup headroom in the outer MCP client deadline, confirm outstanding work and cleanup, then retry.`,
});

const resourceRemediation = (
  context: Readonly<Record<string, unknown>>,
): string => {
  const required = context["requiredMb"];
  return typeof required === "number"
    ? `hbc2js estimated it needs ${String(required)} MB. Set max_heap_mb (setting hbc2js.max_heap_mb) to at least ${String(required)} if the host has the memory, or decompile a smaller function.`
    : "hbc2js reported E_RESOURCE. Raise max_heap_mb (setting hbc2js.max_heap_mb) if the host has the memory, or decompile a smaller function.";
};

/** The command dialect for one run: its deadline, capture allowance and diagnostics. */
const commandDialect =
  (
    operation: string,
    diagnostics: Readonly<Record<string, string>>,
    limits: Hbc2jsRunLimits,
    adjustable: boolean,
    outputLimitBytes: number,
  ) =>
  () => ({
    operation,
    capturedOutput: capturedProviderOutput,
    timeout: adjustable
      ? decompileTimeoutGuidance(limits)
      : {
          ms: DECODE_TIMEOUT_MS,
          userMessage: `hbc2js ${operation} reached its ${String(DECODE_TIMEOUT_MS)} ms deadline`,
          remediationAction: `This ${String(DECODE_TIMEOUT_MS)} ms hbc2js allowance has no runtime override. Allow cleanup headroom in the outer MCP client deadline, confirm outstanding work and cleanup, then retry with a smaller module page.`,
        },
    outputLimit: {
      limits: { max_output_bytes: outputLimitBytes },
      recovery: {
        retryable: false as const,
        remediationAction: hbc2jsOutputLimitRecovery(
          "output_limit_bytes",
          outputLimitBytes,
        ),
      },
      limit: hbc2jsOutputParameterLimit("output_limit_bytes", outputLimitBytes),
    },
    dialect: (
      _exit: unknown,
      _details: unknown,
      unclassified: (extra: {
        diagnostics: typeof diagnostics;
      }) => AnalysisError,
    ) => unclassified({ diagnostics }),
  });

/** Run one hbc2js decoding command and parse its single machine reply. */
export const runHbc2jsMachine = async (
  selection: Hbc2jsCommandSelection,
  argv: readonly string[],
  operation: string,
  resourceOwner: ArtifactResourceScope,
  options: {
    readonly signal?: AbortSignal;
    readonly environment: Readonly<Record<string, string | undefined>>;
    readonly platform: NodeJS.Platform;
    /** Present for decompile; inspection keeps the fixed allowance. */
    readonly limits?: Hbc2jsRunLimits;
    /** The caller's output_limit_bytes; the default applies without it. */
    readonly outputLimitBytes?: number;
  },
): Promise<Hbc2jsMachineReply> => {
  const { signal, platform } = options;
  const limits = options.limits ?? FIXED_LIMITS;
  const outputLimitBytes =
    options.outputLimitBytes ?? HBC2JS_OUTPUT_LIMITS.output_limit_bytes.default;
  const adjustable = options.limits !== undefined;
  const base = snapshotEnvironment(options.environment, platform);
  // The heap flag is a per-call value for this child only; nothing is persisted.
  const hostEnvironment =
    limits.heapMb === null
      ? base
      : {
          ...base,
          NODE_OPTIONS: `--max-old-space-size=${String(limits.heapMb)}`,
        };
  const invocation = hbc2jsInvocation(
    selection,
    argv,
    hostEnvironment,
    platform,
  );
  const diagnostics = {
    selected_command: selection.command,
    command_source: selection.commandSource,
  };
  let parsed: Result<Hbc2jsMachineReply, Hbc2jsOutputFailure> | undefined;
  try {
    await prepareOwnedCommand(signal);
    await runOwnedCommand(
      {
        command: invocation.command,
        arguments: invocation.arguments,
        windowsVerbatimArguments: invocation.windowsVerbatimArguments,
        expectedCommand: null,
        runId: randomUUID(),
        hostEnvironment,
      },
      {
        timeoutMs: limits.timeoutMs,
        diagnosticBytes: outputLimitBytes,
        // hbc2js reports its own failures as a JSON envelope with exit 2.
        acceptNonZeroExit: true,
        observeCompleted: (snapshot) => {
          parsed = parseHbc2jsMachineReply(snapshot.stdout.text);
        },
      },
      signal === undefined ? {} : { signal },
    );
  } catch (cause) {
    const failure = classifyProviderFailure(cause, {
      providerId: HBC2JS_PROVIDER_IDENTITY.id,
      operation,
      command: commandDialect(
        operation,
        diagnostics,
        limits,
        adjustable,
        outputLimitBytes,
      ),
      unclassified: (unclassified, details) =>
        new ProviderAdapterError(HBC2JS_PROVIDER_IDENTITY.id, operation, {
          ...details,
          cause: unclassified,
          diagnostics,
        }),
    });
    const cleanups = retainOwnedCommandCleanup(
      cause,
      retainedScope(resourceOwner),
      HBC2JS_PROVIDER_IDENTITY.id,
      operation,
    );
    throw cleanups.reduce(
      (composed: AnalysisError, cleanup) =>
        analysisErrorWithCleanupDependencies(composed, cleanup, operation),
      failure,
    );
  }
  if (parsed === undefined)
    throw new ProviderAdapterError(HBC2JS_PROVIDER_IDENTITY.id, operation, {
      userMessage: "hbc2js completed without an output observation",
      diagnostics,
    });
  if (!parsed.ok)
    throw new ProviderAdapterError(HBC2JS_PROVIDER_IDENTITY.id, operation, {
      userMessage: `hbc2js ${operation} failed: ${describeHbc2jsOutputFailure(parsed.error)}`,
      ...(parsed.error.kind === "tool_error" &&
      parsed.error.code === "E_RESOURCE"
        ? { remediationAction: resourceRemediation(parsed.error.context) }
        : {}),
      diagnostics: {
        ...diagnostics,
        ...(parsed.error.kind === "tool_error"
          ? {
              hbc2js_error_code: parsed.error.code,
              hbc2js_error_context: parsed.error.context,
            }
          : { output_failure: parsed.error.kind }),
      },
    });
  return parsed.value;
};
