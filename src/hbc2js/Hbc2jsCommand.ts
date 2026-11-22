import { randomUUID } from "node:crypto";

import { AnalysisError } from "../domain/analysisErrorBase.js";
import { analysisErrorWithCleanupDependencies } from "../domain/analysisErrorCleanup.js";
import { fixedAllowanceOptions } from "../domain/fixedAllowanceRemediation.js";
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
  DECODE_MAX_OUTPUT_BYTES,
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
  },
): Promise<Hbc2jsMachineReply> => {
  const { signal, platform } = options;
  const hostEnvironment = snapshotEnvironment(options.environment, platform);
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
        timeoutMs: DECODE_TIMEOUT_MS,
        diagnosticBytes: DECODE_MAX_OUTPUT_BYTES,
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
      command: () => ({
        operation,
        capturedOutput: capturedProviderOutput,
        timeout: {
          ms: DECODE_TIMEOUT_MS,
          userMessage: `hbc2js ${operation} reached its ${String(DECODE_TIMEOUT_MS)} ms deadline`,
          remediationAction: `This ${String(DECODE_TIMEOUT_MS)} ms hbc2js allowance has no runtime override. Allow cleanup headroom in the outer MCP client deadline, confirm outstanding work and cleanup, then retry with a smaller module page.`,
        },
        outputLimit: {
          limits: { max_output_bytes: DECODE_MAX_OUTPUT_BYTES },
          recovery: fixedAllowanceOptions(
            "The hbc2js output capture allowance",
            "capture",
            { limit: DECODE_MAX_OUTPUT_BYTES, unit: "bytes" },
          ),
        },
        dialect: (_exit, _details, unclassified) =>
          unclassified({ diagnostics }),
      }),
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
