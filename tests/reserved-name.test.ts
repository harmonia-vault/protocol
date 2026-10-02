import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { mutationSigningBytes } from "../typescript/wire.ts";
const v = JSON.parse(readFileSync(new URL("../vectors/signatures-v1.json", import.meta.url), "utf8"));
test("拒绝全部大小写形式的 Harmonia 内部变量前缀", () => {
  for (const name of ["__HARMONIA_STATE", "__harmonia_state", "__HaRmOnIa_STATE"]) {
    assert.throws(() => mutationSigningBytes({ ...v.mutation, name }));
  }
});
