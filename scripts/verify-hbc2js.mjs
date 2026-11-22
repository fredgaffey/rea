#!/usr/bin/env node
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { delimiter, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { VerifierFixture } from "./lib/verifier-fixture.mjs";

const execute = promisify(execFile);
const usage =
  "Usage: npm run verify:hbc2js [-- --hbc PATH] [--hermesc PATH]\n" +
  "Requires a caller-selected hbc2js launcher (REA_HBC2JS_COMMAND, absolute,\n" +
  "or hbc2js on PATH) whose --version --json reports machine contract 1.\n" +
  "The sample is --hbc PATH, else tests/fixtures/hbc2js/verify-sample.js\n" +
  "compiled at verify time with hermesc (--hermesc PATH, REA_HERMESC or PATH).\n" +
  "Without hbc2js, contract 1 or a sample the lane skips and claims no\n" +
  "coverage. Nothing is downloaded, installed or checked in as a binary.\n";
const argument = (name) => {
  const at = process.argv.indexOf(name);
  return at === -1 ? null : (process.argv[at + 1] ?? null);
};
if (process.argv.includes("--help")) {
  process.stdout.write(usage);
  process.exit(0);
}
class SkipLane extends Error {}
const skip = (reason) => {
  throw new SkipLane(reason);
};

const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const environment = Object.fromEntries(
  Object.entries(process.env).filter(([, value]) => typeof value === "string"),
);

const findOnPath = async (name) => {
  for (const directory of (environment.PATH ?? "").split(delimiter)) {
    if (directory === "") continue;
    const candidate = join(directory, name);
    try {
      await execute(candidate, ["--version"], { timeout: 20_000 });
      return candidate;
    } catch {
      // keep searching
    }
  }
  return null;
};

const cli = async (args) => {
  const { stdout } = await execute(
    process.execPath,
    [entrypoint, ...args, "--json"],
    {
      env: environment,
      maxBuffer: 64 * 1024 * 1024,
      timeout: 300_000,
    },
  ).catch((cause) => {
    throw new Error(
      `rea ${args[0]} failed: ${cause.stdout ?? ""}${cause.stderr ?? cause.message}`,
    );
  });
  return JSON.parse(stdout).normalized_result;
};

let failures = 0;
const check = (name, condition, detail = "") => {
  process.stdout.write(
    `[${condition ? "ok" : "FAIL"}] ${name}${detail === "" ? "" : ` - ${detail}`}\n`,
  );
  if (!condition) failures += 1;
};

let fixture;
let skipped = null;
try {
  let admitted;
  try {
    admitted = (await cli(["inspect-hbc2js-client"])).client;
  } catch (cause) {
    skip(
      `no usable hbc2js launcher (${String(cause.message).split("\n")[0]}). Set REA_HBC2JS_COMMAND or put hbc2js on PATH.`,
    );
  }
  if (admitted.contract !== 1)
    skip(
      `hbc2js ${admitted.hbc2js_version} reports machine contract ${String(admitted.contract)}; REA admits contract 1`,
    );
  check(
    "hbc2js launcher admitted",
    true,
    `${admitted.command} ${admitted.hbc2js_version} (${admitted.admission})`,
  );

  fixture = await VerifierFixture.open({ prefix: "rea-verify-hbc2js-" });
  let sample = argument("--hbc");
  if (sample === null) {
    const hermesc =
      argument("--hermesc") ??
      environment.REA_HERMESC ??
      (await findOnPath("hermesc"));
    if (hermesc === null)
      skip(
        "no sample: pass --hbc PATH, or provide hermesc (--hermesc, REA_HERMESC or PATH) to compile the source-owned sample",
      );
    if (!isAbsolute(hermesc) && !hermesc.includes("/"))
      skip("hermesc must be a path or on PATH");
    const source = fileURLToPath(
      new URL("../tests/fixtures/hbc2js/verify-sample.js", import.meta.url),
    );
    sample = join(fixture.path, "verify-sample.hbc");
    try {
      await execute(hermesc, ["-emit-binary", "-out", sample, source], {
        timeout: 60_000,
      });
    } catch (cause) {
      skip(
        `hermesc could not compile the sample (${String(cause.message).split("\n")[0]})`,
      );
    }
  }
  const digest = createHash("sha256")
    .update(await readFile(sample))
    .digest("hex");

  const inspected = await cli(["inspect-hermes-bytecode", sample]);
  check(
    "CLI inspect digest matches the file on disk",
    inspected.target.sha256 === digest,
  );
  check(
    "CLI inspect reports a function count",
    inspected.observations.function_count > 0,
    `${inspected.observations.function_count} functions, HBC ${inspected.observations.hbc_version}`,
  );
  const fnIndex = 0;
  const decompiled = await cli([
    "decompile-hermes-function",
    sample,
    "--function-index",
    String(fnIndex),
  ]);
  check("CLI decompile digest matches", decompiled.target.sha256 === digest);
  check(
    "CLI decompile returns source",
    decompiled.source.length > 0 && decompiled.verification.syntax === true,
    `${decompiled.source_bytes} bytes`,
  );
  const none = await cli([
    "decompile-hermes-function",
    sample,
    "--function-index",
    String(fnIndex),
    "--passes",
    "none",
  ]);
  check("CLI decompile honours --passes none", none.passes === "none");
  const capped = await cli([
    "decompile-hermes-function",
    sample,
    "--function-index",
    String(fnIndex),
    "--max-source-bytes",
    "40",
  ]);
  check(
    "CLI decompile truncates with a recovery",
    capped.truncated === true && capped.recovery !== null,
  );

  const client = new Client({ name: "hbc2js-verifier", version: "1" });
  fixture.releaseAfter(() => client.close());
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [entrypoint, "mcp"],
      env: environment,
      stderr: "pipe",
    }),
  );
  const names = (await client.listTools()).tools.map(({ name }) => name);
  for (const name of [
    "inspect_hbc2js_client",
    "inspect_hermes_bytecode",
    "decompile_hermes_function",
  ])
    check(`MCP advertises ${name}`, names.includes(name));
  const call = async (name, args) => {
    const reply = await client.callTool(
      { name, arguments: args },
      { timeout: 300_000 },
    );
    return reply.isError === true
      ? null
      : (reply.structuredContent?.normalized_result ?? null);
  };
  const mcpClient = await call("inspect_hbc2js_client", {});
  check(
    "MCP client probe agrees with the CLI",
    mcpClient?.client.contract === 1,
  );
  const mcpInspect = await call("inspect_hermes_bytecode", { path: sample });
  check(
    "MCP inspect agrees with the CLI",
    mcpInspect?.target.sha256 === digest,
  );
  const mcpDecompile = await call("decompile_hermes_function", {
    path: sample,
    function_index: fnIndex,
  });
  check(
    "MCP decompile source equals the CLI source",
    mcpDecompile?.source === decompiled.source,
  );
  const moduleId = mcpInspect?.derivations.modules.rows[0]?.id;
  if (moduleId !== undefined) {
    const byModule = await call("decompile_hermes_function", {
      path: sample,
      module_id: moduleId,
    });
    check(
      "MCP decompile by module id names its factory",
      byModule?.function.factory_of === moduleId,
    );
  } else {
    process.stdout.write(
      "[skip] module decompile - the sample has no Metro module table\n",
    );
  }
  const refused = await client.callTool({
    name: "decompile_hermes_function",
    arguments: { path: sample, function_index: 0, module_id: 0 },
  });
  check(
    "MCP refuses both function_index and module_id",
    refused.isError === true,
  );
} catch (cause) {
  if (cause instanceof SkipLane) skipped = cause.message;
  else {
    failures += 1;
    process.stdout.write(
      `[FAIL] verifier execution - ${cause instanceof Error ? cause.message : String(cause)}\n`,
    );
  }
} finally {
  try {
    await fixture?.release();
  } catch (cause) {
    failures += 1;
    process.stdout.write(
      `[FAIL] fixture cleanup - ${cause instanceof Error ? cause.message : String(cause)}\n`,
    );
  }
}
if (skipped !== null && failures === 0) {
  process.stdout.write(
    `SKIP verify:hbc2js: ${skipped}\nNo coverage is claimed.\n`,
  );
  process.exit(0);
}
if (failures > 0) {
  process.stdout.write(`\n${failures} check(s) failed\n`);
  process.exit(1);
}
process.stdout.write("\nAll hbc2js checks passed\n");
