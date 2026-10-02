import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, createPrivateKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { mutationSigningBytes, encodeBase64url, maxValueBytes } from "../typescript/wire.ts";
const v = JSON.parse(readFileSync(new URL("../vectors/max-packet-v1.json", import.meta.url), "utf8"));
test("Go/Node 最大 65576 字节数据包互操作并拒绝超限", () => {
  assert.equal(v.packetBytes, maxValueBytes + 40);
  const packet = new Uint8Array(v.packetBytes).fill(v.syntheticPacketFillByte);
  const message = { ...v.mutationTemplate, payload: encodeBase64url(packet) };
  const encoded = mutationSigningBytes(message);
  assert.equal(createHash("sha256").update(encoded).digest("hex"), v.signingSha256);
  const privateKey = createPrivateKey({ format: "der", type: "pkcs8", key: Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(v.syntheticSigningSeedHex, "hex")]) });
  assert.equal(encodeBase64url(sign(null, encoded, privateKey)), v.signature);
  assert.throws(() => mutationSigningBytes({ ...message, payload: encodeBase64url(new Uint8Array(v.packetBytes + 1)) }));
});
