import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verify, hkdfSync, sign } from 'node:crypto';
import { c, b64, h, sk, pk, cert, tv, dv, recordRow, viewBytes, sourceBytes, dagBytes, envelopeHash } from './dag-fixture.ts';
const fixture=JSON.parse(readFileSync(new URL('../vectors/recovery-dag-v1.json',import.meta.url),'utf8'));
test('Go/Node平坦Proof4、Source12和新23/18/16签名域逐字节一致',()=>{
 const p=fixture.proof,b=dagBytes(p);assert.equal(b.toString('hex'),fixture.canonicalHex);assert.equal(h(b),fixture.hash);assert.equal(JSON.parse(b.toString()).length,6);assert.equal(JSON.parse(viewBytes(p.source.view).toString()).length,12);
 const t=p.records.find((r:any)=>r.kind==='transition-v2'&&r.record.submission.transition.authorizationKind==='all-environments-admin').record.submission;
 const d=p.records.find((r:any)=>r.kind==='recovered-v2'&&r.record.sequence===41).record.submission;
 assert.equal(tv(t.transition,'2').toString('hex'),fixture.transitionSigningHex);assert.equal(dv(d.enrollment,'2').toString('hex'),fixture.recoveredSigningHex);
 assert.equal(cert(fixture.approval,'5',fixture.hash).toString('hex'),fixture.certificateSigningHex);
 const shuffled=structuredClone(p);shuffled.records.reverse();assert.deepEqual(dagBytes(shuffled),b);shuffled.source.view.dependencies.reverse();assert.deepEqual(dagBytes(shuffled),b);
});
test('第二次恢复设备完整Admin再次轮换、新恢复自登记双签和明确RO子设备均实际Ed25519验签',()=>{
 const p=fixture.proof,records=[...p.records].sort((a:any,b:any)=>a.record.sequence-b.record.sequence);assert.equal(records.length,5);
 for(const r of records){const s=r.record.submission,ver=r.kind.slice(-1);if(r.kind.startsWith('transition')){
  const bytes=tv(s.transition,ver),author=s.transition.authorizationKind==='old-recovery'?s.transition.oldRecoverySigningPublicKey:p.source.view.authorities.find((a:any)=>a.grant.grant.subjectDeviceId===s.transition.authorizerDeviceId).grant.grant.subjectSigningPublicKey;
  assert(verify(null,bytes,pk(author),Buffer.from(s.authorizationSignature,'base64url')));assert(verify(null,bytes,pk(s.transition.newRecoverySigningPublicKey),Buffer.from(s.newRecoverySignature,'base64url')));
  if(ver==='2')assert(!verify(null,tv(s.transition,'1'),pk(author),Buffer.from(s.authorizationSignature,'base64url')));
  assert.equal(s.transition.environmentManifestHash,h(c(['harmonia/recovery-environment-manifest/v1',s.environmentManifest.map((e:any)=>[e.environmentId,e.keyVersion])])));
  assert.equal(s.transition.envelopesHash,envelopeHash('harmonia/recovery-envelopes/v1',s.envelopes));
  if(s.issuerEvidence)assert.equal(s.transition.issuerEvidenceHash,h(sourceBytes(s.issuerEvidence)));
 }else{const bytes=dv(s.enrollment,ver),transition:any=records.find((x:any)=>x.kind.startsWith('transition')&&recordRow(x)[1]===s.enrollment.recoveryTransitionHash);assert(transition);const recpub=transition.record.submission.transition.newRecoverySigningPublicKey;assert(verify(null,bytes,pk(recpub),Buffer.from(s.recoverySignature,'base64url')));assert(verify(null,bytes,pk(s.enrollment.deviceSigningPublicKey),Buffer.from(s.deviceSignature,'base64url')));if(ver==='2')assert(!verify(null,dv(s.enrollment,'1'),pk(recpub),Buffer.from(s.recoverySignature,'base64url')));}
 }
 const a=fixture.approval,cb=cert(a,'5',fixture.hash);for(const side of ['approver','initiator'])assert(verify(null,cb,pk(a.context[side+'SigningPublicKey']),Buffer.from(a[side+'Signature'],'base64url')));
 assert.equal(a.context.approverDeviceId,'recovered-G');assert(a.grants.every((s:any)=>s.grant.role==='ro'&&s.grant.expiresAt==='2030000200'));assert(!verify(null,cert(a,'4',fixture.hash),pk(a.context.approverSigningPublicKey),Buffer.from(a.approverSignature,'base64url')));
 const derived=hkdfSync('sha256',Buffer.from(fixture.syntheticSeedsHex.thirdRecovery,'hex'),Buffer.alloc(0),c(['harmonia/recovery-kdf/v1','ed25519-signing',p.accountId,p.accountGeneration,'4']),32);
 const third:any=records.find((r:any)=>r.record.submission.transition?.newRecoveryGeneration==='4');assert.equal(b64(sign(null,tv(third.record.submission.transition,'2'),sk(Buffer.from(derived).toString('hex')))),third.record.submission.newRecoverySignature);
});
