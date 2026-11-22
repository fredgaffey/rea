import { afterEach, expect, it } from "vitest";
import { writeHbc2jsLauncher } from "../../tests/fixtures/hbc2jsLauncher.js";
import { HBC2JS_VERIFIED_VERSION } from "./Hbc2jsRelease.js";
import { Hbc2jsCommandCleanup } from "./Hbc2jsCommandCleanup.js";
import { Hbc2jsConfigurationFailure } from "./Hbc2jsConfiguration.js";
import { inspectHbc2jsClient } from "./Hbc2jsVersionProbe.js";

let commands = new Hbc2jsCommandCleanup();
afterEach(async () => {
  await commands.close();
  commands = new Hbc2jsCommandCleanup();
});

const probe = async (mode: string) =>
  inspectHbc2jsClient(
    { command: await writeHbc2jsLauncher(mode), commandSource: "environment" },
    commands,
    { platform: process.platform, environment: process.env },
  );

it("admits the verified release from its --version --json reply", async () => {
  expect(await probe("ok")).toMatchObject({
    version: HBC2JS_VERIFIED_VERSION,
    contract: 1,
    hbcVersions: [84, 94, 96, 98, 99],
    admission: "verified",
    limitations: [],
  });
});

it("admits a newer contract-1 release with the compatible-release limitation", async () => {
  const identity = await probe("newer-version");
  expect(identity).toMatchObject({ version: "0.4.2", admission: "compatible" });
  expect(identity.limitations).toHaveLength(1);
});

it.each([
  ["contract-2", "unsupported_version"],
  ["contract-2-same-schema", "unsupported_version"],
  ["not-json", "version_unresolved"],
  ["error", "version_unresolved"],
])(
  "refuses %s as %s with the selected command in diagnostics",
  async (mode, code) => {
    const failure = await probe(mode).catch((cause: unknown) => cause);
    expect(failure).toBeInstanceOf(Hbc2jsConfigurationFailure);
    expect(failure).toMatchObject({ code });
    expect((failure as Hbc2jsConfigurationFailure).diagnostics).toMatchObject({
      selected_command: expect.stringContaining("hbc2js"),
    });
  },
);

it("reports a missing launcher with the environment repair", async () => {
  const failure = await inspectHbc2jsClient(
    { command: "/nonexistent/hbc2js", commandSource: "environment" },
    commands,
    { platform: process.platform, environment: process.env },
  ).catch((cause: unknown) => cause);
  expect(failure).toMatchObject({
    code: "command_missing",
    remediation: expect.stringContaining("REA_HBC2JS_COMMAND"),
  });
});

it("reports a launcher that exits nonzero as version_unresolved with its exit code and stderr", async () => {
  const failure = await probe("fail-exit").catch((cause: unknown) => cause);
  expect(failure).toBeInstanceOf(Hbc2jsConfigurationFailure);
  expect(failure).toMatchObject({
    code: "version_unresolved",
    diagnostics: {
      exit_code: 1,
      stderr_excerpt: expect.stringContaining("boom"),
    },
  });
});
