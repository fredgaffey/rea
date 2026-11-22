import { z } from "zod";

import type { AnalysisParameterLimit } from "../analysisSettings.js";
import {
  MAXIMUM_HBC2JS_MAX_HEAP_MB,
  MINIMUM_HBC2JS_MAX_HEAP_MB,
  timerDurationMsSchema,
} from "../analysisResourceLimits.js";
import { localPathStringSchema } from "../localPath.js";

/** Per-call bounds on the bytes captured from one hbc2js process. */
export const HBC2JS_OUTPUT_LIMITS = {
  output_limit_bytes: {
    default: 8 * 1024 * 1024,
    maximum: 64 * 1024 * 1024,
  },
  version_output_limit_bytes: {
    default: 64 * 1024,
    maximum: 1024 * 1024,
  },
} as const;
/** An hbc2js output-capture parameter. */
export type Hbc2jsOutputLimitField = keyof typeof HBC2JS_OUTPUT_LIMITS;

/** One accepted hbc2js output-capture parameter, as a request control. */
export const hbc2jsOutputParameterLimit = (
  field: Hbc2jsOutputLimitField,
  effectiveValue: number,
): AnalysisParameterLimit => ({
  control_kind: "parameter",
  parameter: field,
  effective_value: effectiveValue,
  unit: "bytes",
  minimum: 1,
  maximum: HBC2JS_OUTPUT_LIMITS[field].maximum,
  default_value: HBC2JS_OUTPUT_LIMITS[field].default,
  applies_at: "next_call",
});

/** Recovery for an exhausted hbc2js output-capture budget. */
export const hbc2jsOutputLimitRecovery = (
  field: Hbc2jsOutputLimitField,
  effectiveValue: number,
): string =>
  effectiveValue < HBC2JS_OUTPUT_LIMITS[field].maximum
    ? `Pass a larger ${field} (up to ${String(HBC2JS_OUTPUT_LIMITS[field].maximum)} bytes) on the next call; no restart is required.`
    : `${field} is at its maximum of ${String(effectiveValue)} bytes; use a smaller module page or a smaller bytecode file. Repeating the unchanged request fails the same way.`;

const outputLimitSchema = (field: Hbc2jsOutputLimitField, what: string) =>
  z
    .int()
    .positive()
    .max(HBC2JS_OUTPUT_LIMITS[field].maximum)
    .optional()
    .describe(
      `Bytes of ${what} captured per hbc2js process (default ${String(HBC2JS_OUTPUT_LIMITS[field].default)}, at most ${String(HBC2JS_OUTPUT_LIMITS[field].maximum)}); applies on the next call without restart`,
    );
/** Source bytes returned when max_source_bytes is omitted. */
export const DEFAULT_HBC2JS_MAX_SOURCE_BYTES = 256 * 1024;
export const MAXIMUM_HBC2JS_MAX_SOURCE_BYTES = 16 * 1024 * 1024;

/**
 * Caller intent for hbc2js-backed Hermes bytecode analysis. hbc2js is
 * bring-your-own: REA never installs it, and every operation is a static read
 * of the caller's file by a separate process.
 */
export const hbc2jsInputSchemas = {
  inspect_hbc2js_client: z.strictObject({
    version_output_limit_bytes: outputLimitSchema(
      "version_output_limit_bytes",
      "--version --json output",
    ),
  }),
  inspect_hermes_bytecode: z.strictObject({
    path: localPathStringSchema.describe(
      "Local Hermes bytecode (.hbc) file to inspect",
    ),
    module_offset: z
      .int()
      .nonnegative()
      .default(0)
      .describe("Index of the first Metro module row to return"),
    module_limit: z
      .int()
      .min(1)
      .max(1000)
      .default(200)
      .describe("Most Metro module rows to return; page with next_offset"),
    output_limit_bytes: outputLimitSchema(
      "output_limit_bytes",
      "decoding output",
    ),
    version_output_limit_bytes: outputLimitSchema(
      "version_output_limit_bytes",
      "--version --json output",
    ),
  }),
  decompile_hermes_function: z
    .strictObject({
      path: localPathStringSchema.describe(
        "Local Hermes bytecode (.hbc) file to decompile from",
      ),
      function_index: z
        .int()
        .nonnegative()
        .exactOptional()
        .describe(
          "Hermes function index to decompile; give exactly one of function_index and module_id",
        ),
      module_id: z
        .int()
        .nonnegative()
        .exactOptional()
        .describe(
          "Numeric Metro module id; decompiles that module's factory function. Give exactly one of function_index and module_id",
        ),
      passes: z
        .enum(["default", "none"])
        .default("default")
        .describe(
          "default: hbc2js readability passes; none: the structured output without them",
        ),
      decompile_timeout_ms: timerDurationMsSchema
        .exactOptional()
        .describe(
          "Wall-clock budget for the hbc2js decompile process in milliseconds (default 300000; setting hbc2js.decompile_timeout_ms). Omitted uses the runtime setting or the default. Applies on the next call. Does not raise the version-probe deadline; output_limit_bytes bounds the output capture.",
        ),
      max_heap_mb: z
        .int()
        .min(MINIMUM_HBC2JS_MAX_HEAP_MB)
        .max(MAXIMUM_HBC2JS_MAX_HEAP_MB)
        .exactOptional()
        .describe(
          `V8 old-space for the hbc2js process in MiB, passed as NODE_OPTIONS=--max-old-space-size (setting hbc2js.max_heap_mb; range ${String(MINIMUM_HBC2JS_MAX_HEAP_MB)}..${String(MAXIMUM_HBC2JS_MAX_HEAP_MB)}). Omitted uses the runtime setting; unset leaves Node's default. hbc2js fails fast with E_RESOURCE and requiredMb when it needs more.`,
        ),
      max_source_bytes: z
        .int()
        .min(1)
        .max(MAXIMUM_HBC2JS_MAX_SOURCE_BYTES)
        .default(DEFAULT_HBC2JS_MAX_SOURCE_BYTES)
        .describe(
          `Most UTF-8 bytes of source to return (default ${String(DEFAULT_HBC2JS_MAX_SOURCE_BYTES)}); a longer function is cut with truncated:true and a recovery`,
        ),
      output_limit_bytes: outputLimitSchema(
        "output_limit_bytes",
        "decoding output",
      ),
      version_output_limit_bytes: outputLimitSchema(
        "version_output_limit_bytes",
        "--version --json output",
      ),
    })
    .refine(
      (input) =>
        (input.function_index === undefined) !==
        (input.module_id === undefined),
      { message: "Give exactly one of function_index and module_id" },
    ),
};

/** Supported hbc2js-backed operations. */
export type Hbc2jsOperation = keyof typeof hbc2jsInputSchemas;
/** Validated hbc2js requests carry their selected operation. */
export type Hbc2jsRequest = {
  [Name in Hbc2jsOperation]: {
    operation: Name;
    input: z.infer<(typeof hbc2jsInputSchemas)[Name]>;
  };
}[Hbc2jsOperation];

/** Validate operation and input together so their types remain correlated. */
export const hbc2jsRequestSchema = z.discriminatedUnion("operation", [
  z.strictObject({
    operation: z.literal("inspect_hbc2js_client"),
    input: hbc2jsInputSchemas.inspect_hbc2js_client,
  }),
  z.strictObject({
    operation: z.literal("inspect_hermes_bytecode"),
    input: hbc2jsInputSchemas.inspect_hermes_bytecode,
  }),
  z.strictObject({
    operation: z.literal("decompile_hermes_function"),
    input: hbc2jsInputSchemas.decompile_hermes_function,
  }),
]);

const client = z.strictObject({
  command: z.string().min(1),
  command_source: z.enum(["environment", "path"]),
  hbc2js_version: z.string().min(1),
  contract: z.int().describe("hbc2js machine contract; REA admits 1"),
  hbc_versions: z
    .array(z.int().nonnegative())
    .describe("Hermes bytecode versions this hbc2js release accepts"),
  node: z.string().min(1).describe("Node.js version running hbc2js"),
  admission: z
    .enum(["verified", "compatible"])
    .describe(
      "verified: the release REA's parsing was checked against; compatible: another release of the same contract",
    ),
});

const hermesBytecode = z.strictObject({
  target: z
    .strictObject({
      path: z.string().min(1).describe("The path the caller supplied"),
      bytes: z.int().nonnegative().describe("Size REA measured"),
      sha256: z
        .string()
        .regex(/^[0-9a-f]{64}$/u)
        .describe("SHA-256 REA measured; hbc2js reported the same digest"),
    })
    .describe("The file REA read; hbc2js digested the same bytes"),
  observations: z
    .strictObject({
      hbc_version: z.int().nonnegative(),
      function_count: z.int().nonnegative(),
      string_count: z.int().nonnegative(),
      sections: z.array(
        z.strictObject({
          name: z.string(),
          offset: z.int().nonnegative(),
          size: z.int().nonnegative(),
        }),
      ),
    })
    .describe("Header and section-table facts read from the file"),
  derivations: z
    .strictObject({
      probe: z
        .strictObject({
          layout_class: z.string(),
          opcode_table: z.string(),
          chosen: z.string(),
          forced: z.boolean(),
          decided_by: z.array(z.string()),
          exhaustive: z.boolean(),
          sampled_functions: z.int().nonnegative(),
          total_functions: z.int().nonnegative(),
          candidates: z.array(
            z.strictObject({ layout_class: z.string(), passed: z.boolean() }),
          ),
        })
        .describe("The layout and opcode table hbc2js chose, and why"),
      modules: z
        .strictObject({
          metro_detected: z
            .boolean()
            .describe(
              "false means no Metro __d table was found, not that the bundle has no modules",
            ),
          total: z.int().nonnegative(),
          rows: z.array(
            z.strictObject({
              id: z.int().nonnegative().describe("Numeric Metro module id"),
              factory_function: z.int().nonnegative(),
              deps: z.array(z.int().nonnegative()),
              function_count: z.int().nonnegative(),
            }),
          ),
          page: z.strictObject({
            offset: z.int().nonnegative(),
            limit: z.int().positive(),
            next_offset: z.int().nonnegative().nullable(),
          }),
        })
        .describe("Metro module table recovered from the global function"),
    })
    .describe("Conclusions hbc2js drew from the observations"),
  invocation: z.strictObject({
    contract: z.int(),
    caller_input_path: z.string().min(1),
    argv: z.strictObject({
      info: z.array(z.string()),
      modules: z.array(z.string()),
    }),
  }),
});

const target = z
  .strictObject({
    path: z.string().min(1).describe("The path the caller supplied"),
    bytes: z.int().nonnegative(),
    sha256: z.string().regex(/^[0-9a-f]{64}$/u),
  })
  .describe("The file REA read; hbc2js digested the same bytes");

const hermesFunction = z.strictObject({
  target,
  function: z
    .strictObject({
      index: z.int().nonnegative(),
      name: z
        .string()
        .describe("Name hbc2js synthesized or recovered; may be empty"),
      module_id: z.int().nonnegative().nullable(),
      factory_of: z
        .int()
        .nonnegative()
        .nullable()
        .describe("Metro module id this function is the factory of, if any"),
    })
    .describe("The function hbc2js decompiled"),
  source: z.string().describe("Decompiled JavaScript; possibly truncated"),
  source_bytes: z
    .int()
    .nonnegative()
    .describe("UTF-8 bytes of the full source before any truncation"),
  truncated: z.boolean(),
  max_source_bytes: z.int().positive(),
  recovery: z
    .string()
    .nullable()
    .describe("How to get the rest of the source; null when not truncated"),
  passes: z.enum(["default", "none"]),
  verification: z
    .strictObject({ structurer: z.boolean(), syntax: z.boolean() })
    .describe(
      "hbc2js's own self-checks; syntax:false means the source did not parse",
    ),
  invocation: z.strictObject({
    contract: z.int(),
    caller_input_path: z.string().min(1),
    argv: z.array(z.string()),
    max_heap_mb: z.int().nullable(),
    decompile_timeout_ms: z.int().positive(),
  }),
});

/** Portable hbc2js observations. */
export const hbc2jsResultSchemas = {
  inspect_hbc2js_client: z.strictObject({ client }),
  inspect_hermes_bytecode: hermesBytecode,
  decompile_hermes_function: hermesFunction,
};
export type HermesBytecodeResult = z.infer<typeof hermesBytecode>;
export type HermesFunctionResult = z.infer<typeof hermesFunction>;
export type Hbc2jsClient = z.infer<typeof client>;
