import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, onTestFinished } from "vitest";
import { writeHbc2jsLauncher } from "../../tests/fixtures/hbc2jsLauncher.js";
import { HBC2JS_COMMAND_ENV } from "./Hbc2jsConfiguration.js";
import { Hbc2jsProvider } from "./Hbc2jsProvider.js";

const providers: Hbc2jsProvider[] = [];
afterEach(async () => {
  await Promise.all(providers.splice(0).map((provider) => provider.close()));
});
const providerFor = async (mode: string) => {
  const launcher = await writeHbc2jsLauncher(mode);
  const provider = new Hbc2jsProvider({
    environment: { [HBC2JS_COMMAND_ENV]: launcher },
  });
  providers.push(provider);
  return { provider, launcher };
};

it("reports the fake launcher as available", async () => {
  const { provider, launcher } = await providerFor("ok");
  expect(await provider.inspectAvailability()).toMatchObject({
    status: "available",
    diagnostics: { selected_command: launcher, command_source: "environment" },
  });
});

it("returns the resolved client for inspect_hbc2js_client", async () => {
  const { provider, launcher } = await providerFor("ok");
  const result = await provider.execute({
    operation: "inspect_hbc2js_client",
    input: {},
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect(result.value.result).toEqual({
    client: {
      command: launcher,
      command_source: "environment",
      hbc2js_version: "0.1.0",
      contract: 1,
      hbc_versions: [84, 94, 96, 98, 99],
      node: "24.22.1",
      admission: "verified",
    },
  });
  expect(result.value.provider).toMatchObject({
    id: "hbc2js",
    version: "hbc2js@0.1.0",
  });
});

it("refuses an unsupported contract as unavailable and as a configuration refusal", async () => {
  const { provider } = await providerFor("contract-2");
  expect(await provider.inspectAvailability()).toMatchObject({
    status: "unavailable",
    code: "unsupported_version",
  });
  const result = await provider.execute({
    operation: "inspect_hbc2js_client",
    input: {},
  });
  expect(result.ok).toBe(false);
});

it("refuses new work after close", async () => {
  const { provider } = await providerFor("ok");
  await provider.close();
  expect(
    (await provider.execute({ operation: "inspect_hbc2js_client", input: {} }))
      .ok,
  ).toBe(false);
});

describe("inspect_hermes_bytecode", () => {
  const targetBytes = "not really bytecode; the fake launcher only hashes it";
  const targetFile = async (): Promise<{ path: string; sha256: string }> => {
    const directory = await mkdtemp(join(tmpdir(), "rea-hbc-"));
    onTestFinished(() => rm(directory, { recursive: true, force: true }));
    const path = join(directory, "index.android.hbc");
    const bytes = Buffer.from(targetBytes);
    await writeFile(path, bytes);
    return { path, sha256: createHash("sha256").update(bytes).digest("hex") };
  };
  const inspect = async (
    mode: string,
    input: { module_offset?: number; module_limit?: number } = {},
  ) => {
    const { provider } = await providerFor(mode);
    const target = await targetFile();
    const result = await provider.execute({
      operation: "inspect_hermes_bytecode",
      input: {
        path: target.path,
        module_offset: input.module_offset ?? 0,
        module_limit: input.module_limit ?? 200,
      },
    });
    return { result, target };
  };

  it("reports the target digest, header facts, probe decision and module page", async () => {
    const { result, target } = await inspect("ok");
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const value = result.value.result as Record<string, any>;
    expect(value.target).toEqual({
      path: target.path,
      bytes: Buffer.byteLength(targetBytes),
      sha256: target.sha256,
    });
    expect(value.observations).toMatchObject({
      hbc_version: 96,
      function_count: 2,
      string_count: 15,
      sections: [
        { name: "header", offset: 0, size: 128 },
        { name: "functionHeaders", offset: 128, size: 32 },
      ],
    });
    expect(value.derivations.probe).toMatchObject({
      layout_class: "C",
      opcode_table: "hbc96",
      chosen: "C/hbc96",
      decided_by: ["P2", "version"],
      exhaustive: true,
    });
    expect(value.derivations.modules).toEqual({
      metro_detected: true,
      total: 3,
      rows: [
        { id: 0, factory_function: 74, deps: [1, 3], function_count: 2 },
        { id: 1, factory_function: 76, deps: [2], function_count: 5 },
        { id: 2, factory_function: 80, deps: [], function_count: 1 },
      ],
      page: { offset: 0, limit: 200, next_offset: null },
    });
    expect(value.invocation).toMatchObject({
      contract: 1,
      caller_input_path: target.path,
      argv: {
        info: ["--info", target.path, "--json"],
        modules: [
          "modules",
          target.path,
          "--json",
          "--offset",
          "0",
          "--limit",
          "200",
        ],
      },
    });
    expect(result.value.limitations).toEqual(
      expect.arrayContaining([expect.stringContaining("numeric Metro ids")]),
    );
    expect(result.value.provider).toMatchObject({ version: "hbc2js@0.1.0" });
  });

  it("pages the module table", async () => {
    const { result } = await inspect("ok", {
      module_offset: 1,
      module_limit: 1,
    });
    expect(result.ok && result.value.result).toMatchObject({
      derivations: {
        modules: {
          rows: [{ id: 1 }],
          page: { offset: 1, limit: 1, next_offset: 2 },
        },
      },
    });
  });

  it("states metro_detected:false as a fact, not as no modules", async () => {
    const { result } = await inspect("no-metro");
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.result).toMatchObject({
      derivations: { modules: { metro_detected: false, total: 0, rows: [] } },
    });
    expect(result.value.limitations.join("\n")).toMatch(
      /metro_detected is false.*does not mean/su,
    );
  });

  it("turns hbc2js warnings into limitations", async () => {
    const { result } = await inspect("warn");
    expect(result.ok && result.value.limitations).toEqual(
      expect.arrayContaining([expect.stringContaining("W_LAYOUT_ASSUMED")]),
    );
  });

  it("fails when hbc2js digests different bytes than REA", async () => {
    const { result } = await inspect("digest-mismatch");
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(JSON.stringify(result.error, ["userMessage"])).toMatch(/sha256/u);
  });

  it("surfaces an hbc2js error envelope as a provider failure", async () => {
    const { result } = await inspect("info-error");
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(JSON.stringify(result.error, ["userMessage", "message"])).toContain(
      "E_IO",
    );
  });

  it("refuses a missing file before launching anything", async () => {
    const { provider } = await providerFor("ok");
    const result = await provider.execute({
      operation: "inspect_hermes_bytecode",
      input: {
        path: "/nonexistent/x.hbc",
        module_offset: 0,
        module_limit: 200,
      },
    });
    expect(result.ok).toBe(false);
  });
});
