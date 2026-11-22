import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, onTestFinished } from "vitest";

import { writeHbc2jsLauncher } from "../../tests/fixtures/hbc2jsLauncher.js";
import { hbc2jsRequestSchema } from "../domain/hbc2js/hermesBytecode.js";
import { HBC2JS_COMMAND_ENV } from "./Hbc2jsConfiguration.js";
import { Hbc2jsProvider } from "./Hbc2jsProvider.js";

const providers: Hbc2jsProvider[] = [];
afterEach(async () => {
  await Promise.all(providers.splice(0).map((provider) => provider.close()));
});

const start = async (mode: string, extra: Record<string, unknown> = {}) => {
  const provider = new Hbc2jsProvider({
    environment: { [HBC2JS_COMMAND_ENV]: await writeHbc2jsLauncher(mode) },
  });
  providers.push(provider);
  const directory = await mkdtemp(join(tmpdir(), "rea-hbc-"));
  onTestFinished(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, "a.hbc");
  await writeFile(path, "bytes");
  const request = hbc2jsRequestSchema.parse({
    operation: "decompile_hermes_function",
    input: { path, function_index: 3, ...extra },
  });
  return { provider, request };
};

it.skipIf(process.platform === "win32")(
  "ends a hung decompile at decompile_timeout_ms and names the setting",
  async () => {
    const { provider, request } = await start("hang-decompile", {
      decompile_timeout_ms: 400,
    });
    const started = performance.now();
    const result = await provider.execute(request);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(performance.now() - started).toBeLessThan(15_000);
    const text = JSON.stringify(result.error, [
      "userMessage",
      "remediationAction",
      "limit",
      "setting",
    ]);
    expect(text).toContain("hbc2js.decompile_timeout_ms");
    expect(text).toContain("400");
  },
  30_000,
);

it.skipIf(process.platform === "win32")(
  "settles a cancelled decompile of a launcher that ignores SIGTERM",
  async () => {
    const { provider, request } = await start("ignore-sigterm-decompile");
    const controller = new AbortController();
    const pending = provider.execute(request, { signal: controller.signal });
    await new Promise((resolve) => setTimeout(resolve, 1_500));
    controller.abort();
    const outcome = await Promise.race([
      pending,
      new Promise<"unsettled">((resolve) =>
        setTimeout(() => resolve("unsettled"), 20_000),
      ),
    ]);
    expect(outcome).not.toBe("unsettled");
    if (outcome === "unsettled") return;
    expect(outcome.ok).toBe(false);
    // Owned cleanup finishes: close must not hang or throw.
    await expect(provider.close()).resolves.toBeUndefined();
  },
  45_000,
);

it.skipIf(process.platform === "win32")(
  "close cancels an in-flight decompile and releases its process",
  async () => {
    const { provider, request } = await start("hang-decompile");
    const pending = provider.execute(request);
    await new Promise((resolve) => setTimeout(resolve, 1_500));
    await provider.close();
    const result = await pending;
    expect(result.ok).toBe(false);
  },
  45_000,
);
