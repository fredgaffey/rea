import { resolve } from "node:path";
import { z } from "zod";

import { AnalysisProtocolError } from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import type {
  Hbc2jsRequest,
  HermesFunctionResult,
} from "../domain/hbc2js/hermesBytecode.js";
import type { ArtifactResourceScope } from "../resources/index.js";
import { measureTarget } from "./Hbc2jsBytecodeInspection.js";
import { runHbc2jsMachine, type Hbc2jsRunLimits } from "./Hbc2jsCommand.js";
import type { Hbc2jsCommandSelection } from "./Hbc2jsConfiguration.js";
import { HBC2JS_PROVIDER_IDENTITY } from "./Hbc2jsProviderIdentity.js";
import { HBC2JS_CONTRACT } from "./Hbc2jsRelease.js";

const OPERATION = "decompile_hermes_function";
type DecompileRequest = Extract<Hbc2jsRequest, { operation: typeof OPERATION }>;

const functionReply = z.looseObject({
  kind: z.literal("function"),
  input: z.looseObject({ sha256: z.string(), bytes: z.int().nonnegative() }),
  warnings: z.array(z.looseObject({ code: z.string(), message: z.string() })),
  fn: z.int().nonnegative(),
  name: z.string(),
  moduleId: z.int().nonnegative().nullable(),
  factoryOf: z.int().nonnegative().nullable(),
  source: z.string(),
  verified: z.looseObject({ structurer: z.boolean(), syntax: z.boolean() }),
  passes: z.enum(["default", "none"]),
});

/** Cut `text` to at most `maxBytes` UTF-8 bytes without splitting a character. */
const truncateUtf8 = (text: string, maxBytes: number): string => {
  const bytes = Buffer.from(text, "utf8");
  if (bytes.length <= maxBytes) return text;
  let end = maxBytes;
  // Back up over UTF-8 continuation bytes so no character is split.
  while (end > 0 && ((bytes[end] ?? 0) & 0xc0) === 0x80) end -= 1;
  return bytes.subarray(0, end).toString("utf8");
};

/** What `decompile_hermes_function` produced, before Evidence is assembled. */
export interface Hbc2jsFunctionDecompilation {
  readonly result: HermesFunctionResult;
  readonly limitations: readonly string[];
}

/** Digest the target, then ask hbc2js to decompile one function or module factory. */
export interface Hbc2jsDecompileContext {
  readonly selection: Hbc2jsCommandSelection;
  readonly scope: ArtifactResourceScope;
  readonly limits: Hbc2jsRunLimits;
  readonly signal?: AbortSignal;
  readonly environment: Readonly<Record<string, string | undefined>>;
  readonly platform: NodeJS.Platform;
}

const decompileArgv = (
  request: DecompileRequest,
  path: string,
): readonly string[] => [
  "decompile",
  path,
  ...(request.input.function_index === undefined
    ? ["--module", String(request.input.module_id)]
    : ["--fn", String(request.input.function_index)]),
  "--json",
  ...(request.input.passes === "none" ? ["--passes=none"] : []),
];

type FunctionReply = z.infer<typeof functionReply>;

const decompileLimitations = (
  reply: FunctionReply,
  truncation: { readonly shown: number; readonly total: number } | null,
): string[] => {
  const limitations = [
    "The source is a derivation: names are synthesized, not recovered from the original program.",
    "Identifiers captured from enclosing functions are declared by parents not shown and appear free.",
    "hbc2js does not claim semantic equivalence to the bytecode; verification covers structure and syntax only.",
  ];
  if (!reply.verified.syntax)
    limitations.push(
      "The source did not verify: hbc2js reported verified.syntax:false (exit 5). The text is returned as produced and may not parse.",
    );
  if (!reply.verified.structurer)
    limitations.push(
      "hbc2js reported verified.structurer:false: control-flow structuring did not check out for this function.",
    );
  if (truncation !== null)
    limitations.push(
      `The source was truncated at ${String(truncation.shown)} of ${String(truncation.total)} bytes.`,
    );
  const seen = new Set<string>();
  for (const { code, message } of reply.warnings) {
    const line = `${code}: ${message}`;
    if (!seen.has(line)) {
      seen.add(line);
      limitations.push(line);
    }
  }
  return limitations;
};

const parseFunctionReply = (raw: unknown): FunctionReply => {
  const parsed = functionReply.safeParse(raw);
  if (parsed.success) return parsed.data;
  const issues = parsed.error.issues
    .slice(0, 3)
    .map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`)
    .join("; ");
  throw new AnalysisProtocolError(
    `hbc2js function reply does not match the contract-${String(HBC2JS_CONTRACT)} shape (${issues})`,
  );
};

/** Digest the target, then ask hbc2js to decompile one function or module factory. */
export const decompileHermesFunction = async (
  request: DecompileRequest,
  context: Hbc2jsDecompileContext,
): Promise<Hbc2jsFunctionDecompilation> => {
  const { selection, scope, limits, ...options } = context;
  const { path: callerPath, max_source_bytes } = request.input;
  const path = resolve(callerPath);
  const measured = await measureTarget(OPERATION, path, scope, options.signal);
  const argv = decompileArgv(request, path);
  const reply = parseFunctionReply(
    await runHbc2jsMachine(selection, argv, OPERATION, scope, {
      ...options,
      limits,
      ...(request.input.output_limit_bytes === undefined
        ? {}
        : { outputLimitBytes: request.input.output_limit_bytes }),
    }),
  );
  if (
    reply.input.sha256 !== measured.sha256 ||
    reply.input.bytes !== measured.bytes
  )
    throw new ProviderAdapterError(HBC2JS_PROVIDER_IDENTITY.id, OPERATION, {
      userMessage: `hbc2js decompile digested different bytes than REA read: hbc2js reported sha256 ${reply.input.sha256} (${String(reply.input.bytes)} bytes), REA measured sha256 ${measured.sha256} (${String(measured.bytes)} bytes)`,
      remediationAction:
        "The file changed between REA's read and hbc2js's, or the launcher is not reading the path REA named. Retry with a file that is not being written, and check REA_HBC2JS_COMMAND.",
    });

  const sourceBytes = Buffer.byteLength(reply.source, "utf8");
  const truncated = sourceBytes > max_source_bytes;
  const recovery = truncated
    ? `The source is ${String(sourceBytes)} bytes and was cut at ${String(max_source_bytes)}. Raise max_source_bytes to at least ${String(sourceBytes)} (the source is never paged), or decompile a smaller function.`
    : null;
  return {
    result: {
      target: {
        path: callerPath,
        bytes: measured.bytes,
        sha256: measured.sha256,
      },
      function: {
        index: reply.fn,
        name: reply.name,
        module_id: reply.moduleId,
        factory_of: reply.factoryOf,
      },
      source: truncated
        ? truncateUtf8(reply.source, max_source_bytes)
        : reply.source,
      source_bytes: sourceBytes,
      truncated,
      max_source_bytes,
      recovery,
      passes: reply.passes,
      verification: reply.verified,
      invocation: {
        contract: HBC2JS_CONTRACT,
        caller_input_path: callerPath,
        argv: [...argv],
        max_heap_mb: limits.heapMb,
        decompile_timeout_ms: limits.timeoutMs,
      },
    },
    limitations: decompileLimitations(
      reply,
      truncated ? { shown: max_source_bytes, total: sourceBytes } : null,
    ),
  };
};
