import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { expect, it, onTestFinished } from "vitest";

import type { RequestAnalysisPort } from "../../../src/ports/AnalysisProvider.js";
import type { Hbc2jsRequest } from "../../../src/domain/hbc2js/hermesBytecode.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { ok } from "../../../src/domain/result.js";
import { createAnalysisExecution } from "../../../src/ports/AnalysisProvider.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { createMcpSchemaValidation } from "../../fixtures/mcpSchemaValidation.js";
import { assertAdvertisedMcpContracts } from "./mcpContractHarness.js";

const identity = { id: "hbc2js", name: "hbc2js", version: "hbc2js@0.1.2" };

const bytecode = {
  target: {
    path: "/targets/index.android.hbc",
    bytes: 859,
    sha256: "a".repeat(64),
  },
  observations: {
    hbc_version: 96,
    function_count: 2,
    string_count: 15,
    sections: [{ name: "header", offset: 0, size: 128 }],
  },
  derivations: {
    probe: {
      layout_class: "C",
      opcode_table: "hbc96",
      chosen: "C/hbc96",
      forced: false,
      decided_by: ["P2", "version"],
      exhaustive: true,
      sampled_functions: 2,
      total_functions: 2,
      candidates: [{ layout_class: "C", passed: true }],
    },
    modules: {
      metro_detected: true,
      total: 1,
      rows: [{ id: 0, factory_function: 74, deps: [], function_count: 2 }],
      page: { offset: 0, limit: 200, next_offset: null },
    },
  },
  invocation: {
    contract: 1,
    caller_input_path: "/targets/index.android.hbc",
    argv: {
      info: ["--info", "/targets/index.android.hbc", "--json"],
      modules: [
        "modules",
        "/targets/index.android.hbc",
        "--json",
        "--offset",
        "0",
        "--limit",
        "200",
      ],
    },
  },
};

it("advertises exact valid inspect_hermes_bytecode schema and records evidence through MCP", async () => {
  const seen: unknown[] = [];
  const provider: RequestAnalysisPort<Hbc2jsRequest> = {
    async inspectAvailability() {
      return { status: "available", code: null, reason: null, diagnostics: {} };
    },
    async close() {},
    async execute(request) {
      seen.push(request.input);
      return ok(createAnalysisExecution(bytecode, identity));
    },
  };
  const session = createTestBinarySession(() => {
    throw new Error("deep provider must not start");
  });
  const server = createServer(
    { kind: "session", session },
    {
      hbc2jsAnalysis: provider,
      environment: { ...process.env },
    },
  );
  onTestFinished(() => server.close());
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client(
    { name: "hbc2js-boundary", version: "0.0.0" },
    { jsonSchemaValidator: createMcpSchemaValidation() },
  );
  onTestFinished(() => client.close());
  await client.connect(clientTransport);

  const { tools } = await client.listTools();
  assertAdvertisedMcpContracts(["inspect_hermes_bytecode"], tools);

  const reply = await client.callTool({
    name: "inspect_hermes_bytecode",
    arguments: { path: "/targets/index.android.hbc", module_limit: 1 },
  });
  expect(reply.isError).not.toBe(true);
  const evidence = parseEvidence(reply.structuredContent);
  expect(evidence.provider.id).toBe("hbc2js");
  expect(evidence.normalized_result).toMatchObject({
    derivations: { modules: { metro_detected: true } },
  });
  expect(seen).toEqual([
    { path: "/targets/index.android.hbc", module_offset: 0, module_limit: 1 },
  ]);

  const invalid = await client.callTool({
    name: "inspect_hermes_bytecode",
    arguments: { path: "/targets/a.hbc", module_limit: 0 },
  });
  expect(invalid.isError).toBe(true);
  expect(seen).toHaveLength(1);
});

it("advertises decompile_hermes_function and admits exactly one of function_index and module_id", async () => {
  const seen: unknown[] = [];
  const provider: RequestAnalysisPort<Hbc2jsRequest> = {
    inspectAvailability: () =>
      Promise.resolve({
        status: "available",
        code: null,
        reason: null,
        diagnostics: {},
      }),
    close: () => Promise.resolve(),
    execute: (request) => {
      seen.push(request.input);
      return Promise.resolve(
        ok(
          createAnalysisExecution(
            {
              target: bytecode.target,
              function: {
                index: 3,
                name: "i",
                module_id: null,
                factory_of: null,
              },
              source: "function _fn3(a1) {\n  return a1;\n}\n",
              source_bytes: 36,
              truncated: false,
              max_source_bytes: 262144,
              recovery: null,
              passes: "default",
              verification: { structurer: true, syntax: true },
              invocation: {
                contract: 1,
                caller_input_path: bytecode.target.path,
                argv: ["decompile"],
                max_heap_mb: null,
                decompile_timeout_ms: 300000,
              },
            },
            identity,
          ),
        ),
      );
    },
  };
  const session = createTestBinarySession(() => {
    throw new Error("deep provider must not start");
  });
  const server = createServer(
    { kind: "session", session },
    { hbc2jsAnalysis: provider, environment: { ...process.env } },
  );
  onTestFinished(() => server.close());
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client(
    { name: "hbc2js-boundary", version: "0.0.0" },
    { jsonSchemaValidator: createMcpSchemaValidation() },
  );
  onTestFinished(() => client.close());
  await client.connect(clientTransport);

  const { tools } = await client.listTools();
  assertAdvertisedMcpContracts(["decompile_hermes_function"], tools);
  const reply = await client.callTool({
    name: "decompile_hermes_function",
    arguments: { path: "/targets/a.hbc", function_index: 3 },
  });
  expect(reply.isError).not.toBe(true);
  expect(
    parseEvidence(reply.structuredContent).normalized_result,
  ).toMatchObject({ function: { index: 3 }, truncated: false });
  for (const args of [
    { path: "/targets/a.hbc" },
    { path: "/targets/a.hbc", function_index: 1, module_id: 1 },
  ])
    expect(
      (
        await client.callTool({
          name: "decompile_hermes_function",
          arguments: args,
        })
      ).isError,
    ).toBe(true);
  expect(seen).toHaveLength(1);
});
