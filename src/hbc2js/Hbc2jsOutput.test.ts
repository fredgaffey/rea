import { describe, expect, it } from "vitest";
import { parseHbc2jsMachineReply } from "./Hbc2jsOutput.js";

const version = {
  schema: "hbc2js-machine/1",
  kind: "version",
  ok: true,
  hbc2js: "0.1.2",
  contract: 1,
  hbcVersions: [84, 94, 96, 98, 99],
  node: "24.22.1",
};

describe("parseHbc2jsMachineReply", () => {
  it("parses a version reply once, at the boundary", () => {
    const parsed = parseHbc2jsMachineReply(JSON.stringify(version) + "\n");
    expect(parsed).toEqual({ ok: true, value: version });
  });

  it("keeps fields added within contract 1", () => {
    const parsed = parseHbc2jsMachineReply(
      JSON.stringify({ ...version, extra: true }),
    );
    expect(parsed.ok && parsed.value).toMatchObject({ extra: true });
  });

  it.each([
    ["", "empty_output"],
    ["hbc2js 0.1.2\n", "not_json"],
    ["[1]", "schema_mismatch"],
    [JSON.stringify({ ...version, hbcVersions: "96" }), "schema_mismatch"],
    [JSON.stringify({ ...version, schema: "hbc2js-machine/2" }), "schema_tag"],
  ])("rejects %j as %s", (stdout, kind) => {
    const parsed = parseHbc2jsMachineReply(stdout);
    expect(parsed.ok).toBe(false);
    expect(!parsed.ok && parsed.error.kind).toBe(kind);
  });

  it("surfaces the tool's own error envelope with its code and context", () => {
    const parsed = parseHbc2jsMachineReply(
      JSON.stringify({
        schema: "hbc2js-machine/1",
        kind: "error",
        ok: false,
        code: "E_RESOURCE",
        message: "heap too small",
        error: {
          code: "E_RESOURCE",
          message: "heap too small",
          context: { requiredMb: 4096 },
        },
      }),
    );
    expect(!parsed.ok && parsed.error).toMatchObject({
      kind: "tool_error",
      code: "E_RESOURCE",
      context: { requiredMb: 4096 },
    });
  });
});
