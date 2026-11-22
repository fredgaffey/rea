import { expect, it } from "vitest";

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
