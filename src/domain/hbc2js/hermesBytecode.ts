import { z } from "zod";

/**
 * Caller intent for hbc2js-backed Hermes bytecode analysis. hbc2js is
 * bring-your-own: REA never installs it, and every operation is a static read
 * of the caller's file by a separate process.
 */
export const hbc2jsInputSchemas = {
  inspect_hbc2js_client: z.strictObject({}),
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

/** Portable hbc2js observations. */
export const hbc2jsResultSchemas = {
  inspect_hbc2js_client: z.strictObject({ client }),
};
export type Hbc2jsClient = z.infer<typeof client>;
