import { test } from "node:test";
import assert from "node:assert/strict";
import { createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { decodeBase64url } from "../typescript/wire.ts";
const v = JSON.parse(readFileSync(new URL("../vectors/device-session-v1.json", import.meta.url), "utf8"));
const p = v.proof;
const fields = ["harmonia/device-session/v1", p.accountId, p.accountGeneration, p.deviceId,
  p.loginTokenHash, p.challengeId, p.nonce, p.expiresAt];
const key = createPublicKey({ format: "der", type: "spki", key: Buffer.concat([
  Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(decodeBase64url(v.signingPublicKey, 32, 32))]) });
const signature = Buffer.from(decodeBase64url(v.signature, 64, 64));
test("Go/Node 设备持钥会话签名字节与签名互操作", () => {
  const encoded = Buffer.from(JSON.stringify(fields));
  assert.equal(encoded.toString("hex"), v.signingHex);
  assert.equal(verify(null, encoded, key, signature), true);
});
test("持钥证明绑定所有上下文字段", () => {
  for (let i = 1; i < fields.length; i++) {
    const bad = fields.slice(); bad[i] += "x";
    assert.equal(verify(null, Buffer.from(JSON.stringify(bad)), key, signature), false, String(i));
  }
});
