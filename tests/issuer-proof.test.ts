import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verify } from 'node:crypto';
import { grantSigningBytes } from '../typescript/wire.ts';
import { h, pk, cert, dagBytes } from './dag-fixture.ts';
const vector=JSON.parse(readFileSync(new URL('../vectors/environment-origin-v1.json',import.meta.url),'utf8'));
test('普通管理设备通过DAG原初始化和证书5档案建立授权链',()=>{
 const a=vector.approval,p=a.issuerProof;
 assert.equal(p.records.length,0);
 const publicKeys=new Map([[p.source.view.trustRoot.rootDeviceId,p.source.view.trustRoot.rootSigningPublicKey]]);
 for(const path of [p.source.view.path,...p.source.view.identityPaths]) {
  for(const item of path) {
   assert.equal(item.kind,'paired');const n=item.enrollment,c=n.approval.context;
   assert.equal(n.certificateVersion,'5');assert.equal(publicKeys.get(c.approverDeviceId),c.approverSigningPublicKey);
   const bytes=cert(n.approval,'5',n.issuerProofHash);
   assert(verify(null,bytes,pk(c.approverSigningPublicKey),Buffer.from(n.approval.approverSignature,'base64url')));
   assert(verify(null,bytes,pk(c.initiatorSigningPublicKey),Buffer.from(n.approval.initiatorSignature,'base64url')));
   publicKeys.set(c.initiatorDeviceId,c.initiatorSigningPublicKey);
  }
 }
 for(const node of p.source.view.authorities) assert(verify(null,grantSigningBytes(node.grant.grant),pk(publicKeys.get(node.grant.grant.issuerDeviceId) as string),Buffer.from(node.grant.signature,'base64url')));
 assert(verify(null,cert(a,'5',h(dagBytes(p))),pk(a.context.approverSigningPublicKey),Buffer.from(a.approverSignature,'base64url')));
});
test('更换根、身份路径、授权来源或证书域不能沿用已有双签',()=>{
 const a=vector.approval,key=pk(a.context.approverSigningPublicKey),sig=Buffer.from(a.approverSignature,'base64url');
 for(const version of ['1','2','3','4'])assert(!verify(null,cert(a,version,vector.proofHash),key,sig));
 for(const change of [
  (p:any)=>p.source.view.trustRoot.rootDeviceId='other-root',
  (p:any)=>p.source.view.targets[0].authorityHash='0'.repeat(64),
  (p:any)=>p.source.view.path[0].enrollment.approval.context.approverReceivingPublicKey='changed',
  (p:any)=>p.source.view.authorities[1].parentHash='0'.repeat(64),
  (p:any)=>p.initialization.deviceSignature='changed',
 ]){const p=structuredClone(a.issuerProof);change(p);assert(!verify(null,cert(a,'5',h(dagBytes(p))),key,sig));}
 const p=structuredClone(a.issuerProof);p.source.view.authorities.reverse();p.source.view.targets.reverse();assert.equal(h(dagBytes(p)),vector.proofHash);
});
