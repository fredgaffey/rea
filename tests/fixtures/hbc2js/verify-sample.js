// Source for the verify:hbc2js sample. The lane compiles it with hermesc at
// verify time; no compiled bytecode is checked in.
function add(first, second) {
  return first + second;
}
function describe(label, value) {
  return label + ": " + String(value);
}
globalThis.verifySample = describe("sum", add(1, 2));
