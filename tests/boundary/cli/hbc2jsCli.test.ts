import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it, onTestFinished } from "vitest";

import { writeHbc2jsLauncher } from "../../fixtures/hbc2jsLauncher.js";

import {
  expectConfigurationRefusal,
  serveCli as serve,
} from "./cliServeHarness.js";

const MISSING_HBC2JS =
  process.platform === "win32"
    ? "C:\\nonexistent\\hbc2js"
    : "/nonexistent/hbc2js";

it.each([
  [
    MISSING_HBC2JS,
    `The selected hbc2js launcher was not found: ${MISSING_HBC2JS}. Set REA_HBC2JS_COMMAND`,
  ],
  [
    "relative/hbc2js",
    "REA_HBC2JS_COMMAND must be an absolute path to the hbc2js launcher.",
  ],
])(
  "inspect-hbc2js-client with REA_HBC2JS_COMMAND=%s names the host requirement",
  async (command, reason) => {
    const result = await serve(["inspect-hbc2js-client", "--json"], {
      REA_HBC2JS_COMMAND: command,
    });
    expectConfigurationRefusal(result, reason);
  },
);

it("inspect-hermes-bytecode reports the digest and a paged module table", async () => {
  const launcher = await writeHbc2jsLauncher("ok");
  const directory = await mkdtemp(join(tmpdir(), "rea-hbc-cli-"));
  onTestFinished(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, "a.hbc");
  await writeFile(path, "bytes");
  const result = await serve(
    ["inspect-hermes-bytecode", path, "--module-limit", "1", "--json"],
    { REA_HBC2JS_COMMAND: launcher },
  );
  expect(result.exitCode, result.stdout).toBe(0);
  const evidence = JSON.parse(result.stdout) as {
    normalized_result: Record<string, any>;
  };
  expect(evidence.normalized_result.target.sha256).toMatch(/^[0-9a-f]{64}$/u);
  expect(evidence.normalized_result.derivations.modules.rows).toHaveLength(1);
});

it("inspect-hermes-bytecode names a digest mismatch", async () => {
  const launcher = await writeHbc2jsLauncher("digest-mismatch");
  const directory = await mkdtemp(join(tmpdir(), "rea-hbc-cli-"));
  onTestFinished(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, "a.hbc");
  await writeFile(path, "bytes");
  const result = await serve(["inspect-hermes-bytecode", path, "--json"], {
    REA_HBC2JS_COMMAND: launcher,
  });
  expect(result.exitCode).not.toBe(0);
  expect(result.stdout).toContain("sha256");
});
