import { resolve } from "node:path";
import { z } from "zod";

import { AnalysisError } from "../domain/analysisErrorBase.js";
import { AnalysisProtocolError } from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import type {
  HermesBytecodeResult,
  Hbc2jsRequest,
} from "../domain/hbc2js/hermesBytecode.js";
import { errorMessage } from "../kernel/errorMessage.js";
import { RegularFileCleanupFailure } from "../filesystem/OwnedRegularFile.js";
import {
  hashStableFile,
  stableFileHashCause,
} from "../filesystem/StableFileHash.js";
import { classifyProviderFailure } from "../providers/classifyProviderFailure.js";
import { AnalysisCleanupLease } from "../resources/index.js";
import type { ArtifactResourceScope } from "../resources/index.js";
import { runHbc2jsMachine } from "./Hbc2jsCommand.js";
import type { Hbc2jsCommandSelection } from "./Hbc2jsConfiguration.js";
import { HBC2JS_CONTRACT } from "./Hbc2jsRelease.js";
import { HBC2JS_PROVIDER_IDENTITY } from "./Hbc2jsProviderIdentity.js";

const OPERATION = "inspect_hermes_bytecode";

const warning = z.looseObject({ code: z.string(), message: z.string() });
const input = z.looseObject({
  sha256: z.string(),
  bytes: z.int().nonnegative(),
});
const infoReply = z.looseObject({
  kind: z.literal("info"),
  input,
  warnings: z.array(warning),
  version: z.int().nonnegative(),
  layoutClass: z.string(),
  opcodeTable: z.string(),
  probe: z.looseObject({
    candidates: z.array(
      z.looseObject({ layoutClass: z.string(), passed: z.boolean() }),
    ),
    chosen: z.string(),
    forced: z.boolean(),
    decidedBy: z.array(z.string()),
    exhaustive: z.boolean(),
    sampledFunctions: z.int().nonnegative(),
    totalFunctions: z.int().nonnegative(),
  }),
  functionCount: z.int().nonnegative(),
  stringCount: z.int().nonnegative(),
  sections: z.array(
    z.looseObject({
      name: z.string(),
      offset: z.int().nonnegative(),
      size: z.int().nonnegative(),
    }),
  ),
});
const modulesReply = z.looseObject({
  kind: z.literal("modules"),
  input,
  warnings: z.array(warning),
  metro: z.boolean(),
  total: z.int().nonnegative(),
  offset: z.int().nonnegative(),
  rows: z.array(
    z.looseObject({
      id: z.int().nonnegative(),
      factoryFn: z.int().nonnegative(),
      deps: z.array(z.int().nonnegative()),
      fnCount: z.int().nonnegative(),
    }),
  ),
  next: z.int().nonnegative().nullable(),
});

const protocolFailure = (message: string): AnalysisProtocolError =>
  new AnalysisProtocolError(message);

const parseReply = <T>(
  schema: z.ZodType<T>,
  reply: unknown,
  kind: string,
): T => {
  const parsed = schema.safeParse(reply);
  if (parsed.success) return parsed.data;
  const issues = parsed.error.issues
    .slice(0, 3)
    .map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`)
    .join("; ");
  throw protocolFailure(
    `hbc2js ${kind} reply does not match the contract-${String(HBC2JS_CONTRACT)} shape (${issues})`,
  );
};

/** REA's own size and digest of the target, read through a retained descriptor. */
const measureTarget = async (
  path: string,
  scope: ArtifactResourceScope,
  signal: AbortSignal | undefined,
): Promise<{ readonly sha256: string; readonly bytes: number }> => {
  try {
    return await hashStableFile(path, {
      ...(signal === undefined ? {} : { signal }),
      retainFailedClose: (owner) => {
        const lease = AnalysisCleanupLease.forCloseOwner(owner, path);
        scope.retain({
          kind: "lease",
          resource: path,
          lease,
        });
      },
    });
  } catch (cause) {
    const physical = stableFileHashCause(
      cause instanceof RegularFileCleanupFailure ? cause.cleanupCause : cause,
    );
    throw physical instanceof AnalysisError
      ? physical
      : classifyProviderFailure(physical, {
          providerId: HBC2JS_PROVIDER_IDENTITY.id,
          operation: OPERATION,
          file: { path, description: "Hermes bytecode file" },
          unclassified: (unclassified, details) =>
            new ProviderAdapterError(HBC2JS_PROVIDER_IDENTITY.id, OPERATION, {
              ...details,
              cause: unclassified,
              userMessage: `Cannot read the Hermes bytecode file ${path}: ${errorMessage(unclassified)}`,
            }),
        });
  }
};

/** What `inspect_hermes_bytecode` produced, before Evidence is assembled. */
export interface Hbc2jsBytecodeInspection {
  readonly result: HermesBytecodeResult;
  readonly limitations: readonly string[];
}

/** Digest the target, then ask hbc2js for --info and one module page. */
export const inspectHermesBytecode = async (
  request: Extract<Hbc2jsRequest, { operation: typeof OPERATION }>,
  selection: Hbc2jsCommandSelection,
  scope: ArtifactResourceScope,
  options: {
    readonly signal?: AbortSignal;
    readonly environment: Readonly<Record<string, string | undefined>>;
    readonly platform: NodeJS.Platform;
  },
): Promise<Hbc2jsBytecodeInspection> => {
  const { path: callerPath, module_offset, module_limit } = request.input;
  const path = resolve(callerPath);
  const measured = await measureTarget(path, scope, options.signal);

  const infoArgv = ["--info", path, "--json"];
  const modulesArgv = [
    "modules",
    path,
    "--json",
    "--offset",
    String(module_offset),
    "--limit",
    String(module_limit),
  ];
  const info = parseReply(
    infoReply,
    await runHbc2jsMachine(selection, infoArgv, OPERATION, scope, options),
    "info",
  );
  const modules = parseReply(
    modulesReply,
    await runHbc2jsMachine(selection, modulesArgv, OPERATION, scope, options),
    "modules",
  );
  for (const [kind, reported] of [
    ["info", info.input],
    ["modules", modules.input],
  ] as const)
    if (
      reported.sha256 !== measured.sha256 ||
      reported.bytes !== measured.bytes
    )
      throw new ProviderAdapterError(HBC2JS_PROVIDER_IDENTITY.id, OPERATION, {
        userMessage: `hbc2js ${kind} digested different bytes than REA read: hbc2js reported sha256 ${reported.sha256} (${String(reported.bytes)} bytes), REA measured sha256 ${measured.sha256} (${String(measured.bytes)} bytes)`,
        remediationAction:
          "The file changed between REA's read and hbc2js's, or the launcher is not reading the path REA named. Retry with a file that is not being written, and check REA_HBC2JS_COMMAND.",
      });

  const limitations = [
    "Module ids are numeric Metro ids; hbc2js recovers no module file names.",
    "The probe choice and the module table are derivations: the module table comes from scanning the global function's __d calls.",
  ];
  if (!modules.metro)
    limitations.push(
      "metro_detected is false: no Metro __d module table was found in the global function. That is a fact about this bundle's structure and does not mean it has no modules.",
    );
  const seen = new Set<string>();
  for (const { code, message } of [...info.warnings, ...modules.warnings]) {
    const line = `${code}: ${message}`;
    if (!seen.has(line)) {
      seen.add(line);
      limitations.push(line);
    }
  }

  return {
    result: {
      target: {
        path: callerPath,
        bytes: measured.bytes,
        sha256: measured.sha256,
      },
      observations: {
        hbc_version: info.version,
        function_count: info.functionCount,
        string_count: info.stringCount,
        sections: info.sections.map(({ name, offset, size }) => ({
          name,
          offset,
          size,
        })),
      },
      derivations: {
        probe: {
          layout_class: info.layoutClass,
          opcode_table: info.opcodeTable,
          chosen: info.probe.chosen,
          forced: info.probe.forced,
          decided_by: info.probe.decidedBy,
          exhaustive: info.probe.exhaustive,
          sampled_functions: info.probe.sampledFunctions,
          total_functions: info.probe.totalFunctions,
          candidates: info.probe.candidates.map(({ layoutClass, passed }) => ({
            layout_class: layoutClass,
            passed,
          })),
        },
        modules: {
          metro_detected: modules.metro,
          total: modules.total,
          rows: modules.rows.map((row) => ({
            id: row.id,
            factory_function: row.factoryFn,
            deps: row.deps,
            function_count: row.fnCount,
          })),
          page: {
            offset: modules.offset,
            limit: module_limit,
            next_offset: modules.next,
          },
        },
      },
      invocation: {
        contract: HBC2JS_CONTRACT,
        caller_input_path: callerPath,
        argv: { info: infoArgv, modules: modulesArgv },
      },
    },
    limitations,
  };
};
