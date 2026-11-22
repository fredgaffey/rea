import { afterEach, expect, it } from "vitest";

import { writeHbc2jsLauncher } from "../../tests/fixtures/hbc2jsLauncher.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import { Hbc2jsCommandCleanup } from "./Hbc2jsCommandCleanup.js";
import { inspectHbc2jsClient } from "./Hbc2jsVersionProbe.js";

let commands = new Hbc2jsCommandCleanup();
afterEach(async () => {
  await commands.close();
  commands = new Hbc2jsCommandCleanup();
});

it.skipIf(process.platform === "win32")(
  "settles a cancelled probe of a hung launcher that ignores SIGTERM",
  async () => {
    const controller = new AbortController();
    const started = performance.now();
    const probe = inspectHbc2jsClient(
      {
        command: await writeHbc2jsLauncher("ignore-sigterm"),
        commandSource: "environment",
      },
      commands,
      {
        signal: controller.signal,
        environment: process.env,
        platform: process.platform,
      },
    ).catch((cause: unknown) => cause);
    // Let the launcher start before cancelling it.
    await new Promise((resolve) => setTimeout(resolve, 1_000));
    controller.abort();
    // A regressed probe never settles; bound the wait.
    const outcome = await Promise.race([
      probe,
      new Promise((resolve) => setTimeout(() => resolve("unsettled"), 15_000)),
    ]);
    expect(outcome).toBeInstanceOf(AnalysisCancelledError);
    expect(performance.now() - started).toBeLessThan(15_000);
  },
);
