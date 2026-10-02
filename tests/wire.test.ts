import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createPublicKey, createPrivateKey, sign, verify } from "node:crypto";
import { mutationSigningBytes, grantSigningBytes, decodeBase64url } from "../typescript/wire.ts";
const vectors = JSON.parse(readFileSync(new URL("../vectors/signatures-v1.json", import.meta.url), "utf8"));
const publicKey = createPublicKey({ format: "der", type: "spki", key: Buffer.concat([
  Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(decodeBase64url(vectors.signingPublicKey, 32, 32))]) });
const privateKey = createPrivateKey({ format: "der", type: "pkcs8", key: Buffer.concat([
  Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(vectors.syntheticSigningSeedHex, "hex")]) });
for (const [kind, bytes] of [["mutation", mutationSigningBytes], ["grant", grantSigningBytes]] as const) {
  test(`Go/Node ${kind} 签名字节和签名互操作`, () => {
    const message = vectors[kind]; const encoded = bytes(message);
    assert.equal(Buffer.from(encoded).toString("hex"), vectors[`${kind}SigningHex`]);
    const signature = Buffer.from(decodeBase64url(message.signature, 64, 64));
    assert.equal(verify(null, encoded, publicKey, signature), true);
    assert.deepEqual(sign(null, encoded, privateKey), signature);
  });
  test(`${kind} 每个字段都被签名绑定`, () => {
    const message = vectors[kind]; const signature = Buffer.from(decodeBase64url(message.signature, 64, 64));
    for (const field of Object.keys(message).filter(k => k !== "signature")) {
      const bad = { ...message, [field]: message[field] + "x" };
      let accepted = false;
      try { accepted = verify(null, bytes(bad), publicKey, signature); } catch { /* 非规范输入也必须关闭接受 */ }
      assert.equal(accepted, false, field);
    }
  });
}
test("非规范编码和超限必须拒绝", () => {
  for (const accountGeneration of ["01", "0", "+1", "-1", "1.0", "18446744073709551616"]) {
    assert.throws(() => mutationSigningBytes({ ...vectors.mutation, accountGeneration }));
  }
  for (const accountId of ["", "中文", "a b", "<script>", "a".repeat(129)]) {
    assert.throws(() => mutationSigningBytes({ ...vectors.mutation, accountId }));
  }
  for (const payload of [vectors.mutation.payload + "=", "AA\nAA", "AB"]) {
    assert.throws(() => mutationSigningBytes({ ...vectors.mutation, payload }));
  }
  assert.throws(() => decodeBase64url("AB", 1, 1));
  assert.throws(() => mutationSigningBytes({ ...vectors.mutation, operation: "delete" }));
  assert.throws(() => grantSigningBytes({ ...vectors.grant, role: "none" }));
});
test("写操作和管理授权的签名域不同", () => {
  const signature = Buffer.from(decodeBase64url(vectors.mutation.signature, 64, 64));
  assert.equal(verify(null, grantSigningBytes(vectors.grant), publicKey, signature), false);
});
