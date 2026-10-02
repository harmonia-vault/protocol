import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash,createPrivateKey,createPublicKey,sign,verify} from 'node:crypto';
import {grantSigningBytes} from '../typescript/wire.ts';
const v=JSON.parse(readFileSync(new URL('../vectors/environment-origin-v1.json',import.meta.url),'utf8'));
const c=(x:unknown)=>Buffer.from(JSON.stringify(x),'utf8');
const b64=(b:Uint8Array)=>Buffer.from(b).toString('base64url');
const h=(b:Uint8Array)=>createHash('sha256').update(b).digest('hex');
const sk=(seed:string)=>createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.from(seed,'hex')]),format:'der',type:'pkcs8'});
const pk=(b:string)=>createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(b,'base64url')]),format:'der',type:'spki'});
const gh=(s:any)=>h(c(['harmonia/issuer-authority/v1',b64(grantSigningBytes(s.grant)),s.signature]));
const grhash=(gr:any[])=>h(c([...gr].sort((a,b)=>a.grant.environmentId<b.grant.environmentId?-1:a.grant.environmentId>b.grant.environmentId?1:0).map(s=>[s.grant.environmentId,b64(grantSigningBytes(s.grant)),s.signature])));
function originBytes(o:any){
 const rows=(rs:any[])=>rs.map(r=>[r.subjectDeviceId,r.subjectSigningPublicKey,r.subjectReceivingPublicKey,r.keyVersion,r.grantGeneration,r.role,r.expiresAt,r.grantHash]);
 return c(['harmonia/environment-origin/v1',o.accountId,o.accountGeneration,o.actorDeviceId,o.environmentId,o.operation,o.authorityEnvironmentId,o.authorityKeyVersion,o.authorityGrantGeneration,o.previousKeyVersion,o.keyVersion,o.expectedSequence,o.idempotencyKey,o.changeHash,o.authorityHash,rows(o.before),rows(o.after)]);
}
const oh=(s:any)=>h(c(['harmonia/environment-origin-ref/v1',b64(originBytes(s.origin)),s.signature]));
function cert(a:any,version:string,proofHash:string){const x=a.context;const f=['harmonia/device-enrollment/v'+version,a.pairingProfile,x.accountId,x.accountGeneration,x.sessionId,x.challengeNonce,x.expiresAt,x.initiatorDeviceId,x.initiatorSigningPublicKey,x.initiatorReceivingPublicKey,x.approverDeviceId,x.approverSigningPublicKey,x.approverReceivingPublicKey,a.transcriptHash,grhash(a.grants)];if(version!=='1')f.push(proofHash);return c(f)}
function proofBytes(p:any){
 const r=p.trustRoot,rb=c(['harmonia/trust-root/v1',p.accountId,p.accountGeneration,r.rootDeviceId,r.rootSigningPublicKey,r.rootReceivingPublicKey,r.recoveryGeneration,r.recoverySigningPublicKey,r.recoveryReceivingPublicKey]);
 const path=(ps:any[])=>ps.map(n=>[n.certificateVersion,b64(cert(n.approval,n.certificateVersion,n.issuerProofHash)),n.approval.approverSignature,n.approval.initiatorSignature]);
 const as=[...p.authorities].sort((a,b)=>{const x=a.grant.grant,y=b.grant.grant;for(const k of ['environmentId','subjectDeviceId'])if(x[k]!==y[k])return x[k]<y[k]?-1:1;return BigInt(x.grantGeneration)<BigInt(y.grantGeneration)?-1:BigInt(x.grantGeneration)>BigInt(y.grantGeneration)?1:0}).map(a=>[a.grant.grant.environmentId,a.grant.grant.subjectDeviceId,a.grant.grant.grantGeneration,b64(grantSigningBytes(a.grant.grant)),a.grant.signature,a.parentHash,a.originHash,a.previousGrantHash]);
 const ts=[...p.targets].sort((a,b)=>a.environmentId<b.environmentId?-1:a.environmentId>b.environmentId?1:0).map(t=>[t.environmentId,t.authorityHash]);
 const os=p.origins.map((s:any)=>[oh(s),b64(originBytes(s.origin)),s.signature]).sort((a:string[],b:string[])=>a[0]<b[0]?-1:a[0]>b[0]?1:0);
 const branches=p.identityPaths.map(path).sort((a:any,b:any)=>JSON.stringify(a)<JSON.stringify(b)?-1:JSON.stringify(a)>JSON.stringify(b)?1:0);
 return c(['harmonia/issuer-proof/v2',p.accountId,p.accountGeneration,[b64(rb),r.signature],path(p.path),as,ts,os,branches]);
}
test('Go/Node 环境来源17项、proof9项和证书v3精确互操作',()=>{
 assert.equal(originBytes(v.rotation.origin.origin).toString('hex'),v.rotationSigningHex);
 assert.equal(originBytes(v.creation.origin.origin).toString('hex'),v.creationSigningHex);
 assert.equal(oh(v.rotation.origin),v.rotationHash);
 const p=v.approval.issuerProof;assert.equal(proofBytes(p).toString('hex'),v.proofCanonicalHex);assert.equal(h(proofBytes(p)),v.proofHash);
 const cb=cert(v.approval,'3',v.proofHash);assert.equal(cb.toString('hex'),v.certificateSigningHex);
 for(const [name,s] of [['B',v.approval.approverSignature],['D',v.approval.initiatorSignature]])assert.equal(b64(sign(null,cb,sk(v.syntheticSigningSeedsHex[name]))),s);
 const bp=pk(v.approval.context.approverSigningPublicKey);assert(verify(null,originBytes(v.rotation.origin.origin),bp,Buffer.from(v.rotation.origin.signature,'base64url')));
 for(const s of p.origins)assert(verify(null,originBytes(s.origin),bp,Buffer.from(s.signature,'base64url')));
});
test('轮换并列永久接收者和临时管理者两父来源，来源不含数据字段',()=>{
 const o=v.rotation.origin.origin,p=v.approval.issuerProof,byhash=new Map(p.authorities.map((a:any)=>[gh(a.grant),a]));
 assert.equal(o.before[0].expiresAt,'0');assert.notEqual(o.before[1].expiresAt,'0');assert.equal(o.after[0].expiresAt,'0');
 for(let i=0;i<o.after.length;i++){const a:any=byhash.get(o.after[i].grantHash);assert.equal(a.parentHash,o.authorityHash);assert.equal(a.previousGrantHash,o.before[i].grantHash);assert.equal(a.originHash,v.rotationHash)}
 for(const f of ['labelPayload','mutations','recoveryEnvelope','payload','name'])assert(!JSON.stringify(v.rotation.origin).includes('"'+f+'"'));
});
test('来源字段替换、证书降级及proof来源删除拒绝沿用原签名',()=>{
 const original=v.rotation.origin,bp=pk(v.approval.context.approverSigningPublicKey);
 for(const field of ['accountId','accountGeneration','actorDeviceId','environmentId','operation','authorityEnvironmentId','authorityKeyVersion','authorityGrantGeneration','previousKeyVersion','keyVersion','expectedSequence','idempotencyKey','changeHash','authorityHash']){const changed=structuredClone(original);changed.origin[field]+='x';assert(!verify(null,originBytes(changed.origin),bp,Buffer.from(original.signature,'base64url')))}
 for(const field of ['before','after']){const changed=structuredClone(original);changed.origin[field][0].grantHash='0'.repeat(64);assert(!verify(null,originBytes(changed.origin),bp,Buffer.from(original.signature,'base64url')))}
 assert(!verify(null,cert(v.approval,'2',v.proofHash),bp,Buffer.from(v.approval.approverSignature,'base64url')));
 const altered=structuredClone(v.approval);altered.issuerProof.origins=[];assert(!verify(null,cert(altered,'3',h(proofBytes(altered.issuerProof))),bp,Buffer.from(v.approval.approverSignature,'base64url')));
});
