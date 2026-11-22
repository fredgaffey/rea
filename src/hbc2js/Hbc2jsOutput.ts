import { z } from "zod";
import { errorMessage } from "../kernel/errorMessage.js";
import { jsonValueSchema } from "../domain/jsonValue.js";
import { err, ok, type Result } from "../domain/result.js";
import type { Hbc2jsOutputFailure } from "./Hbc2jsFailures.js";

/** Schema tag every hbc2js JSON reply carries. */
export const HBC2JS_MACHINE_SCHEMA = "hbc2js-machine/1";

const envelope = {
  schema: z.literal(HBC2JS_MACHINE_SCHEMA),
  ok: z.literal(true),
  hbc2js: z.string().min(1),
};

/** `hbc2js --version --json`. Loose: contract 1 only ever adds fields. */
export const hbc2jsVersionReplySchema = z.looseObject({
  ...envelope,
  kind: z.literal("version"),
  contract: z.int(),
  hbcVersions: z.array(z.int().nonnegative()),
  node: z.string(),
});
export type Hbc2jsVersionReply = z.infer<typeof hbc2jsVersionReplySchema>;

/** Any other successful reply; later landings parse their own kinds. */
const otherReplySchema = z.looseObject({
  ...envelope,
  kind: z.string().min(1),
});
export type Hbc2jsOtherReply = z.infer<typeof otherReplySchema>;

export type Hbc2jsMachineReply = Hbc2jsVersionReply | Hbc2jsOtherReply;

export const isHbc2jsVersionReply = (
  reply: Hbc2jsMachineReply,
): reply is Hbc2jsVersionReply => reply.kind === "version";

const errorReplySchema = z.looseObject({
  schema: z.literal(HBC2JS_MACHINE_SCHEMA),
  kind: z.literal("error"),
  ok: z.literal(false),
  error: z.looseObject({
    code: z.string().min(1),
    message: z.string(),
    context: z.record(z.string(), jsonValueSchema).default({}),
  }),
});

const issuesOf = (error: z.ZodError): string =>
  error.issues
    .slice(0, 3)
    .map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`)
    .join("; ");

/**
 * Parse one hbc2js stdout reply, once, at the process boundary. Everything
 * downstream receives a typed reply or a tagged failure, never raw JSON.
 */
export const parseHbc2jsMachineReply = (
  stdout: string,
): Result<Hbc2jsMachineReply, Hbc2jsOutputFailure> => {
  if (stdout.trim() === "") return err({ kind: "empty_output" });
  let value: unknown;
  try {
    value = JSON.parse(stdout);
  } catch (cause) {
    return err({
      kind: "not_json",
      message: errorMessage(cause),
    });
  }
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return err({ kind: "schema_mismatch", issues: "reply is not an object" });
  const tag = (value as { schema?: unknown }).schema;
  if (typeof tag === "string" && tag !== HBC2JS_MACHINE_SCHEMA)
    return err({ kind: "schema_tag", schema: tag });
  if ((value as { kind?: unknown }).kind === "error") {
    const failure = errorReplySchema.safeParse(value);
    return failure.success
      ? err({
          kind: "tool_error",
          code: failure.data.error.code,
          message: failure.data.error.message,
          context: failure.data.error.context,
        })
      : err({ kind: "schema_mismatch", issues: issuesOf(failure.error) });
  }
  const reply =
    (value as { kind?: unknown }).kind === "version"
      ? hbc2jsVersionReplySchema.safeParse(value)
      : otherReplySchema.safeParse(value);
  return reply.success
    ? ok(reply.data)
    : err({ kind: "schema_mismatch", issues: issuesOf(reply.error) });
};
