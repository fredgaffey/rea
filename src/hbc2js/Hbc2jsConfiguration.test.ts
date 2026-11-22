import { describe, expect, it } from "vitest";
import {
  HBC2JS_COMMAND_ENV,
  Hbc2jsConfigurationFailure,
  hbc2jsConfigurationAvailability,
  hbc2jsInvocation,
  resolveHbc2jsCommand,
} from "./Hbc2jsConfiguration.js";

describe("resolveHbc2jsCommand", () => {
  it("prefers an absolute REA_HBC2JS_COMMAND", async () => {
    expect(
      await resolveHbc2jsCommand(
        { [HBC2JS_COMMAND_ENV]: "/opt/hbc2js/bin/hbc2js" },
        "linux",
      ),
    ).toEqual({
      command: "/opt/hbc2js/bin/hbc2js",
      commandSource: "environment",
    });
  });

  it("leaves POSIX PATH lookup to process creation", async () => {
    expect(await resolveHbc2jsCommand({}, "linux")).toEqual({
      command: "hbc2js",
      commandSource: "path",
    });
    expect(
      await resolveHbc2jsCommand({ [HBC2JS_COMMAND_ENV]: "  " }, "darwin"),
    ).toEqual({ command: "hbc2js", commandSource: "path" });
  });

  it("rejects a relative environment path with the repair", async () => {
    const failure = await resolveHbc2jsCommand(
      { [HBC2JS_COMMAND_ENV]: "bin/hbc2js" },
      "linux",
    ).catch((cause: unknown) => cause);
    expect(failure).toBeInstanceOf(Hbc2jsConfigurationFailure);
    expect(failure).toMatchObject({
      code: "not_absolute",
      remediation: expect.stringContaining(HBC2JS_COMMAND_ENV),
    });
  });

  it("stops before searching when cancelled", async () => {
    await expect(
      resolveHbc2jsCommand({}, "linux", AbortSignal.abort()),
    ).rejects.toThrow();
  });
});

describe("hbc2jsInvocation", () => {
  it("runs the selected launcher directly on POSIX", () => {
    expect(
      hbc2jsInvocation(
        { command: "/x/hbc2js", commandSource: "environment" },
        ["--version", "--json"],
        {},
        "linux",
      ),
    ).toEqual({
      command: "/x/hbc2js",
      arguments: ["--version", "--json"],
      windowsVerbatimArguments: false,
    });
  });
});

describe("hbc2jsConfigurationAvailability", () => {
  it.each([
    ["command_missing", "executable_missing"],
    ["not_absolute", "not_configured"],
    ["unsupported_version", "unsupported_version"],
    ["version_unresolved", "version_unresolved"],
  ] as const)("maps %s to %s", (code, rejection) => {
    const availability = hbc2jsConfigurationAvailability(
      new Hbc2jsConfigurationFailure(code, "m", "r", { a: 1 }),
    );
    expect(availability).toMatchObject({
      status: "unavailable",
      code: rejection,
      reason: "m",
      remediation: "r",
    });
  });
});
