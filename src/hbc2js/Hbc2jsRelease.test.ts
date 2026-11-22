import { describe, expect, it } from "vitest";
import {
  admitHbc2jsVersion,
  HBC2JS_CONTRACT,
  HBC2JS_VERIFIED_VERSION,
} from "./Hbc2jsRelease.js";

const reply = (overrides: Record<string, unknown> = {}) => ({
  hbc2js: HBC2JS_VERIFIED_VERSION,
  contract: HBC2JS_CONTRACT,
  hbcVersions: [96],
  node: "24.22.1",
  ...overrides,
});

describe("admitHbc2jsVersion", () => {
  it("verifies the release the adapter was written against", () => {
    expect(admitHbc2jsVersion(reply())).toEqual({
      status: "verified",
      version: HBC2JS_VERIFIED_VERSION,
    });
  });

  it("admits another release of contract 1 with a disclosed limitation", () => {
    const admission = admitHbc2jsVersion(reply({ hbc2js: "0.4.2" }));
    expect(admission).toMatchObject({ status: "compatible", version: "0.4.2" });
    expect(admission.status === "compatible" && admission.limitation).toMatch(
      /0\.4\.2.*contract 1/u,
    );
  });

  it("refuses any other contract", () => {
    expect(admitHbc2jsVersion(reply({ contract: 2 }))).toMatchObject({
      status: "unsupported",
      message: expect.stringMatching(/contract 2/u),
    });
  });
});
