import type { JsonValue } from "../domain/jsonValue.js";

/** The ways one hbc2js stdout reply can fail to be a `hbc2js-machine/1` reply. */
export type Hbc2jsOutputFailure =
  | { readonly kind: "empty_output" }
  | { readonly kind: "not_json"; readonly message: string }
  | { readonly kind: "schema_mismatch"; readonly issues: string }
  | { readonly kind: "schema_tag"; readonly schema: string }
  | {
      /** hbc2js answered with its own JSON error envelope. */
      readonly kind: "tool_error";
      readonly code: string;
      readonly message: string;
      readonly context: Readonly<Record<string, JsonValue>>;
    };

/** One-line, caller-safe description of a reply failure. */
export const describeHbc2jsOutputFailure = (
  failure: Hbc2jsOutputFailure,
): string => {
  switch (failure.kind) {
    case "empty_output":
      return "empty stdout";
    case "not_json":
      return `stdout is not JSON (${failure.message})`;
    case "schema_mismatch":
      return `reply does not match hbc2js-machine/1 (${failure.issues})`;
    case "schema_tag":
      return `unsupported schema tag ${JSON.stringify(failure.schema)}`;
    case "tool_error":
      return `hbc2js reported ${failure.code}: ${failure.message}`;
  }
};
