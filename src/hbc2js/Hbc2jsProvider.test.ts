import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, onTestFinished } from "vitest";
import {
  HBC2JS_OUTPUT_LIMITS,
  hbc2jsInputSchemas,
} from "../domain/hbc2js/hermesBytecode.js";
import { writeHbc2jsLauncher } from "../../tests/fixtures/hbc2jsLauncher.js";
import { HBC2JS_COMMAND_ENV } from "./Hbc2jsConfiguration.js";
import { hbc2jsRequestSchema } from "../domain/hbc2js/hermesBytecode.js";
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
      hbc2js_version: "0.1.2",
      contract: 1,
      hbc_versions: [84, 94, 96, 98, 99],
      node: "24.22.1",
      admission: "verified",
    },
  });
  expect(result.value.provider).toMatchObject({
    id: "hbc2js",
    version: "hbc2js@0.1.2",
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
    expect(result.value.provider).toMatchObject({ version: "hbc2js@0.1.2" });
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

describe("output capture limits", () => {
  const ownDirectory = async () => {
    const directory = await mkdtemp(join(tmpdir(), "rea-hbc-limit-"));
    onTestFinished(() => rm(directory, { recursive: true, force: true }));
    const path = join(directory, "index.android.hbc");
    await writeFile(path, "bytes");
    return path;
  };

  it("accepts, defaults and bounds the parameters", () => {
    const client = hbc2jsInputSchemas.inspect_hbc2js_client;
    const inspect = hbc2jsInputSchemas.inspect_hermes_bytecode;
    expect(client.parse({})).toEqual({});
    expect(client.parse({ version_output_limit_bytes: 1024 })).toMatchObject({
      version_output_limit_bytes: 1024,
    });
    expect(
      inspect.parse({ path: "/x.hbc" }).output_limit_bytes,
    ).toBeUndefined();
    expect(
      inspect.parse({ path: "/x.hbc", output_limit_bytes: 1 }),
    ).toMatchObject({ output_limit_bytes: 1 });
    for (const bad of [0, -1, 1.5]) {
      expect(
        client.safeParse({ version_output_limit_bytes: bad }).success,
      ).toBe(false);
      expect(
        inspect.safeParse({ path: "/x.hbc", output_limit_bytes: bad }).success,
      ).toBe(false);
    }
    expect(
      client.safeParse({
        version_output_limit_bytes:
          HBC2JS_OUTPUT_LIMITS.version_output_limit_bytes.maximum + 1,
      }).success,
    ).toBe(false);
    expect(
      inspect.safeParse({
        path: "/x.hbc",
        output_limit_bytes: HBC2JS_OUTPUT_LIMITS.output_limit_bytes.maximum + 1,
      }).success,
    ).toBe(false);
  });

  it("applies version_output_limit_bytes to the version probe and reports the control", async () => {
    const { provider } = await providerFor("ok");
    const result = await provider.execute({
      operation: "inspect_hbc2js_client",
      input: { version_output_limit_bytes: 8 },
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(JSON.stringify(result.error)).toMatch(/version_output_limit_bytes/u);
    const unbounded = await provider.execute({
      operation: "inspect_hbc2js_client",
      input: {},
    });
    expect(unbounded.ok).toBe(true);
  });

  it("applies output_limit_bytes to decoding output and reports the control", async () => {
    const { provider } = await providerFor("ok");
    const path = await ownDirectory();
    const small = await provider.execute({
      operation: "inspect_hermes_bytecode",
      input: {
        path,
        module_offset: 0,
        module_limit: 200,
        output_limit_bytes: 8,
      },
    });
    expect(small.ok).toBe(false);
    if (small.ok) return;
    expect(JSON.stringify(small.error)).toMatch(/output_limit_bytes/u);
    const normal = await provider.execute({
      operation: "inspect_hermes_bytecode",
      input: { path, module_offset: 0, module_limit: 200 },
    });
    expect(normal.ok).toBe(true);
  });
});

describe("decompile_hermes_function", () => {
  const target = async (): Promise<{ path: string; sha256: string }> => {
    const directory = await mkdtemp(join(tmpdir(), "rea-hbc-"));
    onTestFinished(() => rm(directory, { recursive: true, force: true }));
    const path = join(directory, "index.android.hbc");
    const bytes = Buffer.from("fake bytecode");
    await writeFile(path, bytes);
    return { path, sha256: createHash("sha256").update(bytes).digest("hex") };
  };
  const decompile = async (
    mode: string,
    input: Record<string, unknown>,
    options: {
      settings?: Record<string, number>;
    } = {},
  ) => {
    const launcher = await writeHbc2jsLauncher(mode);
    const provider = new Hbc2jsProvider({
      environment: { [HBC2JS_COMMAND_ENV]: launcher },
      ...(options.settings === undefined
        ? {}
        : {
            settings: () => ({ revision: 1, overrides: options.settings! }),
          }),
    });
    providers.push(provider);
    const file = await target();
    const result = await provider.execute(
      hbc2jsRequestSchema.parse({
        operation: "decompile_hermes_function",
        input: { path: file.path, ...input },
      }),
    );
    return { result, file };
  };

  it("decompiles a function index as a derivation with its limitations", async () => {
    const { result, file } = await decompile("ok", { function_index: 3 });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const value = result.value.result as Record<string, any>;
    expect(value).toMatchObject({
      target: { path: file.path, sha256: file.sha256 },
      function: { index: 3, name: "i", module_id: null, factory_of: null },
      passes: "default",
      verification: { structurer: true, syntax: true },
      truncated: false,
      recovery: null,
    });
    expect(value.source).toContain("function _fn3(a1)");
    expect(value.invocation.argv).toEqual([
      "decompile",
      file.path,
      "--fn",
      "3",
      "--json",
    ]);
    expect(result.value.limitations.join("\n")).toMatch(
      /names are synthesized/u,
    );
    expect(result.value.limitations.join("\n")).toMatch(/appear free/u);
    expect(result.value.limitations.join("\n")).toMatch(
      /does not claim semantic equivalence/u,
    );
  });

  it("decompiles a module factory and passes --passes=none", async () => {
    const { result } = await decompile("ok", { module_id: 2, passes: "none" });
    expect(result.ok && result.value.result).toMatchObject({
      function: { index: 76, module_id: 2, factory_of: 2 },
      passes: "none",
      invocation: {
        argv: expect.arrayContaining(["--module", "2", "--passes=none"]),
      },
    });
  });

  it("returns the source with a limitation when verification fails (exit 5)", async () => {
    const { result } = await decompile("verify-fail", { function_index: 3 });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.result).toMatchObject({
      verification: { syntax: false },
    });
    expect(result.value.limitations.join("\n")).toMatch(/did not verify/u);
  });

  it("caps the source at max_source_bytes and names the recovery", async () => {
    const { result } = await decompile("big-source", {
      function_index: 3,
      max_source_bytes: 100,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const value = result.value.result as Record<string, any>;
    expect(value.truncated).toBe(true);
    expect(Buffer.byteLength(value.source)).toBeLessThanOrEqual(100);
    expect(value.source_bytes).toBeGreaterThan(100);
    expect(value.recovery).toContain("max_source_bytes");
    expect(result.value.limitations.join("\n")).toMatch(/truncated/u);
  });

  it("refuses both or neither of function_index and module_id", () => {
    for (const input of [
      { path: "/x.hbc" },
      { path: "/x.hbc", function_index: 1, module_id: 1 },
    ])
      expect(
        hbc2jsRequestSchema.safeParse({
          operation: "decompile_hermes_function",
          input,
        }).success,
      ).toBe(false);
  });

  it("passes max_heap_mb as NODE_OPTIONS to the child, request over setting", async () => {
    const { result } = await decompile(
      "ok",
      { function_index: 3, max_heap_mb: 2048 },
      { settings: { "hbc2js.max_heap_mb": 512 } },
    );
    expect(result.ok && (result.value.result as any).source).toContain(
      "NODE_OPTIONS=--max-old-space-size=2048",
    );
    const fromSetting = await decompile(
      "ok",
      { function_index: 3 },
      { settings: { "hbc2js.max_heap_mb": 512 } },
    );
    expect(
      fromSetting.result.ok && (fromSetting.result.value.result as any).source,
    ).toContain("NODE_OPTIONS=--max-old-space-size=512");
    const unset = await decompile("ok", { function_index: 3 });
    expect(
      unset.result.ok && (unset.result.value.result as any).source,
    ).toMatch(/NODE_OPTIONS=\n/u);
  });

  it("reports E_RESOURCE with requiredMb and the setting id as recovery", async () => {
    const { result } = await decompile("resource", { function_index: 3 });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    const text = JSON.stringify(result.error, [
      "userMessage",
      "remediationAction",
      "diagnostics",
      "hbc2js_error_context",
      "requiredMb",
    ]);
    expect(text).toContain("4096");
    expect(text).toContain("hbc2js.max_heap_mb");
  });
});
