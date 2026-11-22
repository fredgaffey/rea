import { afterEach, expect, it } from "vitest";
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
