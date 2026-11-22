import { z } from "zod";

import { localPathStringSchema } from "../localPath.js";

/**
 * Caller intent for hbc2js-backed Hermes bytecode analysis. hbc2js is
 * bring-your-own: REA never installs it, and every operation is a static read
 * of the caller's file by a separate process.
 */
export const hbc2jsInputSchemas = {
  inspect_hbc2js_client: z.strictObject({}),
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
  }),
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

/** Portable hbc2js observations. */
export const hbc2jsResultSchemas = {
  inspect_hbc2js_client: z.strictObject({ client }),
  inspect_hermes_bytecode: hermesBytecode,
};
export type HermesBytecodeResult = z.infer<typeof hermesBytecode>;
export type Hbc2jsClient = z.infer<typeof client>;
