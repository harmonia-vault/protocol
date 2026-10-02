import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash, createPrivateKey, createPublicKey, hkdfSync, sign, verify } from "node:crypto";
import { grantSigningBytes, mutationSigningBytes } from "../typescript/wire.ts";

// 这里只独立验证公开 Go 向量的字节和标准签名，不代替生产信任/权限验证器。
const vector = JSON.parse(readFileSync(new URL("../vectors/issuer-proof-v1.json", import.meta.url), "utf8"));
const canonical = (value: unknown) => Buffer.from(JSON.stringify(value), "utf8");
const b64 = (value: Uint8Array) => Buffer.from(value).toString("base64url");
const hash = (value: Uint8Array) => createHash("sha256").update(value).digest("hex");
const edPrivate = (seed: string | Uint8Array) => createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), typeof seed === "string" ? Buffer.from(seed, "hex") : Buffer.from(seed)]), format: "der", type: "pkcs8" });
const edPublic = (value: string) => createPublicKey({key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(value, "base64url")]), format: "der", type: "spki"});
const ownPublic = (seed: string | Uint8Array) => b64(createPublicKey(edPrivate(seed)).export({format: "der", type: "spki"}).subarray(-32));
const authorityHash = (signed: any) => hash(canonical(["harmonia/issuer-authority/v1", b64(grantSigningBytes(signed.grant)), signed.signature]));
function grantsHash(grants: any[]) {
  return hash(canonical([...grants].sort((a, b) => a.grant.environmentId < b.grant.environmentId ? -1 : a.grant.environmentId > b.grant.environmentId ? 1 : 0).map(s => [s.grant.environmentId, b64(grantSigningBytes(s.grant)), s.signature])));
}
function rootBytes(proof: any) {
  const r = proof.trustRoot;
  return canonical(["harmonia/trust-root/v1", proof.accountId, proof.accountGeneration, r.rootDeviceId, r.rootSigningPublicKey, r.rootReceivingPublicKey, r.recoveryGeneration, r.recoverySigningPublicKey, r.recoveryReceivingPublicKey]);
}
function certificateBytes(approval: any, version: string, issuerProofHash: string) {
  const c = approval.context;
  const fields = ["harmonia/device-enrollment/" + (version === "2" ? "v2" : "v1"), approval.pairingProfile, c.accountId, c.accountGeneration, c.sessionId, c.challengeNonce, c.expiresAt,
    c.initiatorDeviceId, c.initiatorSigningPublicKey, c.initiatorReceivingPublicKey, c.approverDeviceId, c.approverSigningPublicKey, c.approverReceivingPublicKey, approval.transcriptHash, grantsHash(approval.grants)];
  if (version === "2") fields.push(issuerProofHash);
  return canonical(fields);
}
function proofBytes(proof: any) {
  const path = proof.path.map((n: any) => [n.certificateVersion, b64(certificateBytes(n.approval, n.certificateVersion, n.issuerProofHash)), n.approval.approverSignature, n.approval.initiatorSignature]);
  const authorities = [...proof.authorities].sort((a, b) => {
    const x = a.grant.grant, y = b.grant.grant;
    if (x.environmentId !== y.environmentId) return x.environmentId < y.environmentId ? -1 : 1;
    if (x.subjectDeviceId !== y.subjectDeviceId) return x.subjectDeviceId < y.subjectDeviceId ? -1 : 1;
    return BigInt(x.grantGeneration) < BigInt(y.grantGeneration) ? -1 : BigInt(x.grantGeneration) > BigInt(y.grantGeneration) ? 1 : 0;
  }).map(a => [a.grant.grant.environmentId, a.grant.grant.subjectDeviceId, a.grant.grant.grantGeneration, b64(grantSigningBytes(a.grant.grant)), a.grant.signature, a.parentHash]);
  const targets = [...proof.targets].sort((a, b) => a.environmentId < b.environmentId ? -1 : a.environmentId > b.environmentId ? 1 : 0).map(t => [t.environmentId, t.authorityHash]);
  return canonical(["harmonia/issuer-proof/v1", proof.accountId, proof.accountGeneration, [b64(rootBytes(proof)), proof.trustRoot.signature], path, authorities, targets]);
}
function signatureValid(bytes: Uint8Array, signature: string, publicKey: string) { return verify(null, bytes, edPublic(publicKey), Buffer.from(signature, "base64url")); }

test("签发者证明 Go/Node 固定数组、摘要和 v2 双签相同", () => {
  const a = vector.approval, p = a.issuerProof;
  assert.equal(proofBytes(p).toString("hex"), vector.proofCanonicalHex);
  assert.equal(hash(proofBytes(p)), vector.proofHash);
  const bytes = certificateBytes(a, "2", vector.proofHash);
  assert.equal(bytes.toString("hex"), vector.certificateSigningHex);
  assert.equal(ownPublic(vector.syntheticSigningSeedsHex.B), a.context.approverSigningPublicKey);
  assert.equal(ownPublic(vector.syntheticSigningSeedsHex.C), a.context.initiatorSigningPublicKey);
  assert.equal(b64(sign(null, bytes, edPrivate(vector.syntheticSigningSeedsHex.B))), a.approverSignature);
  assert.equal(b64(sign(null, bytes, edPrivate(vector.syntheticSigningSeedsHex.C))), a.initiatorSignature);
  for (const entry of p.authorities) assert.equal(authorityHash(entry.grant), vector.authorityHashes[entry.grant.grant.subjectDeviceId.slice(-1)]);
});

test("已知合成 B 锚认证历史双签父设备与逐环境 Admin 来源", () => {
  const a = vector.approval, p = a.issuerProof;
  // 真实客户端的 B 锚来自 PAKE；向量以独立本地合成私钥重建，禁止 server root TOFU。
  assert.equal(ownPublic(vector.syntheticSigningSeedsHex.A), p.trustRoot.rootSigningPublicKey);
  assert.equal(ownPublic(vector.syntheticSigningSeedsHex.B), a.context.approverSigningPublicKey);
  const recoverySeed = new Uint8Array(hkdfSync("sha256", Buffer.from(vector.syntheticRecoverySeedHex, "hex"), Buffer.alloc(0), canonical(["harmonia/recovery-kdf/v1", "ed25519-signing", p.accountId, p.accountGeneration, p.trustRoot.recoveryGeneration]), 32));
  assert.equal(ownPublic(recoverySeed), p.trustRoot.recoverySigningPublicKey);
  assert(signatureValid(rootBytes(p), p.trustRoot.signature, ownPublic(recoverySeed)));
  for (const node of p.path) {
    const c = node.approval.context, bytes = certificateBytes(node.approval, node.certificateVersion, node.issuerProofHash);
    assert.equal(c.approverSigningPublicKey, ownPublic(vector.syntheticSigningSeedsHex.A));
    assert.equal(c.initiatorSigningPublicKey, ownPublic(vector.syntheticSigningSeedsHex.B));
    assert(signatureValid(bytes, node.approval.approverSignature, c.approverSigningPublicKey));
    assert(signatureValid(bytes, node.approval.initiatorSignature, c.initiatorSigningPublicKey));
  }
  for (const entry of p.authorities) assert(signatureValid(grantSigningBytes(entry.grant.grant), entry.grant.signature, ownPublic(vector.syntheticSigningSeedsHex.A)));
  assert(signatureValid(grantSigningBytes(a.grants[0].grant), a.grants[0].signature, ownPublic(vector.syntheticSigningSeedsHex.B)));
  assert(signatureValid(mutationSigningBytes(vector.historicalMutation), vector.historicalMutation.signature, ownPublic(vector.syntheticSigningSeedsHex.A)));
});

test("服务器改变 root/目标/路径或把 v2 退成 v1 都不能沿用 B 签名", () => {
  const original = vector.approval, knownB = ownPublic(vector.syntheticSigningSeedsHex.B);
  assert(!signatureValid(certificateBytes(original, "1", ""), original.approverSignature, knownB));
  for (const mutate of [
    (p: any) => p.trustRoot.rootDeviceId = "server-root",
    (p: any) => p.targets[0].authorityHash = "0".repeat(64),
    (p: any) => p.path[0].approval.context.approverReceivingPublicKey = b64(Buffer.alloc(32, 80)),
    (p: any) => p.authorities[0].parentHash = "1".repeat(64),
  ]) {
    const a = structuredClone(original); mutate(a.issuerProof);
    assert(!signatureValid(certificateBytes(a, "2", hash(proofBytes(a.issuerProof))), original.approverSignature, knownB));
  }
});

test("公开证明中 authorities 和 targets 排序不依赖 JSON 对象顺序", () => {
  const p = structuredClone(vector.approval.issuerProof); p.authorities.reverse(); p.targets.reverse();
  assert.equal(hash(proofBytes(p)), vector.proofHash);
});
