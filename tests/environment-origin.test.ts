import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {sign,verify} from 'node:crypto';
import { b64,h,sk,pk,gh,originBytes,oh,cert,dagBytes } from './dag-fixture.ts';
const v=JSON.parse(readFileSync(new URL('../vectors/environment-origin-v1.json',import.meta.url),'utf8'));
test('Go/Node 环境来源17项、DAG和证书v5精确互操作',()=>{
 assert.equal(originBytes(v.rotation.origin.origin).toString('hex'),v.rotationSigningHex);
 assert.equal(originBytes(v.creation.origin.origin).toString('hex'),v.creationSigningHex);
 assert.equal(oh(v.rotation.origin),v.rotationHash);
 const p=v.approval.issuerProof;assert.equal(dagBytes(p).toString('hex'),v.proofCanonicalHex);assert.equal(h(dagBytes(p)),v.proofHash);
 const cb=cert(v.approval,'5',v.proofHash);assert.equal(cb.toString('hex'),v.certificateSigningHex);
 for(const [name,s] of [['B',v.approval.approverSignature],['D',v.approval.initiatorSignature]])assert.equal(b64(sign(null,cb,sk(v.syntheticSigningSeedsHex[name]))),s);
 const bp=pk(v.approval.context.approverSigningPublicKey);assert(verify(null,originBytes(v.rotation.origin.origin),bp,Buffer.from(v.rotation.origin.signature,'base64url')));
 for(const s of p.source.view.origins)assert(verify(null,originBytes(s.origin),bp,Buffer.from(s.signature,'base64url')));
});
test('轮换并列永久接收者和临时管理者两父来源，来源不含数据字段',()=>{
 const o=v.rotation.origin.origin,p=v.approval.issuerProof,byhash=new Map(p.source.view.authorities.map((a:any)=>[gh(a.grant),a]));
 assert.equal(o.before[0].expiresAt,'0');assert.notEqual(o.before[1].expiresAt,'0');assert.equal(o.after[0].expiresAt,'0');
 for(let i=0;i<o.after.length;i++){const a:any=byhash.get(o.after[i].grantHash);assert.equal(a.parentHash,o.authorityHash);assert.equal(a.previousGrantHash,o.before[i].grantHash);assert.equal(a.originHash,v.rotationHash)}
 for(const f of ['labelPayload','mutations','recoveryEnvelope','payload','name'])assert(!JSON.stringify(v.rotation.origin).includes('"'+f+'"'));
});
test('来源字段替换、证书降级及proof来源删除拒绝沿用原签名',()=>{
 const original=v.rotation.origin,bp=pk(v.approval.context.approverSigningPublicKey);
 for(const field of ['accountId','accountGeneration','actorDeviceId','environmentId','operation','authorityEnvironmentId','authorityKeyVersion','authorityGrantGeneration','previousKeyVersion','keyVersion','expectedSequence','idempotencyKey','changeHash','authorityHash']){const changed=structuredClone(original);changed.origin[field]+='x';assert(!verify(null,originBytes(changed.origin),bp,Buffer.from(original.signature,'base64url')))}
 for(const field of ['before','after']){const changed=structuredClone(original);changed.origin[field][0].grantHash='0'.repeat(64);assert(!verify(null,originBytes(changed.origin),bp,Buffer.from(original.signature,'base64url')))}
 assert(!verify(null,cert(v.approval,'2',v.proofHash),bp,Buffer.from(v.approval.approverSignature,'base64url')));
 const altered=structuredClone(v.approval);altered.issuerProof.source.view.origins=[];assert(!verify(null,cert(altered,'5',h(dagBytes(altered.issuerProof))),bp,Buffer.from(v.approval.approverSignature,'base64url')));
});
