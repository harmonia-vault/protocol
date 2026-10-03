import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash,createPrivateKey,createPublicKey,hkdfSync,sign,verify} from 'node:crypto';
import {grantSigningBytes} from '../typescript/wire.ts';
const v=JSON.parse(readFileSync(new URL('../vectors/recovery-authority-v1.json',import.meta.url),'utf8'));
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

const tf=['accountId','accountGeneration','operationId','challengeId','nonce','expiresAt','sessionHash','expectedSequence','previousTransitionHash','oldRecoveryGeneration','oldRecoverySigningPublicKey','oldRecoveryReceivingPublicKey','newRecoveryGeneration','newRecoverySigningPublicKey','newRecoveryReceivingPublicKey','authorizationKind','authorizerDeviceId','environmentManifestHash','authoritySetHash','issuerEvidenceHash','envelopesHash','newTrustRootHash','chainMode','legacyStateHash'];
const df=['accountId','accountGeneration','recoveryGeneration','recoveryTransitionHash','operationId','challengeId','nonce','expiresAt','restrictedSessionHash','expectedSequence','deviceId','deviceSigningPublicKey','deviceReceivingPublicKey','selectedRightsHash','grantsHash','issuerEvidenceHash','envelopesHash'];
const tb=(x:any)=>c(['harmonia/recovery-authority-transition/v1',...tf.map(k=>x[k])]);
const db=(x:any)=>c(['harmonia/recovered-device-enrollment/v1',...df.map(k=>x[k])]);
const tr=(r:any)=>c(['harmonia/trust-root/v1',v.rootPin.AccountID,v.rootPin.AccountGeneration,r.rootDeviceId,r.rootSigningPublicKey,r.rootReceivingPublicKey,r.recoveryGeneration,r.recoverySigningPublicKey,r.recoveryReceivingPublicKey]);
const transitionRef=(s:any)=>h(c(['harmonia/recovery-authority-transition-ref/v1',b64(tb(s.transition)),s.authorizationSignature,s.newRecoverySignature]));
const deviceRef=(s:any)=>h(c(['harmonia/recovered-device-enrollment-ref/v1',b64(db(s.enrollment)),s.recoverySignature,s.deviceSignature]));
const envelopeHash=(domain:string,rows:any[])=>h(c([domain,rows.map(e=>[e.environmentId,e.keyVersion,e.envelope])]));
const evidenceHash=(p:any)=>h(c(['harmonia/recovery-issuer-evidence-ref/v1',p.profile,b64(proofBytes(p))]));
function recoverySeed(name:string,generation:string){return Buffer.from(hkdfSync('sha256',Buffer.from(v.syntheticSeedsHex[name],'hex'),Buffer.alloc(0),c(['harmonia/recovery-kdf/v1','ed25519-signing',v.rootPin.AccountID,v.rootPin.AccountGeneration,generation]),32)).toString('hex')}
function initBytes(){
 const o=v.originalInitialization,p=o.proposal;
 const envs=p.environments.map((e:any)=>[e.environmentId,e.keyVersion,e.recoveryEnvelope,b64(grantSigningBytes(e.grant.grant)),e.grant.signature]);
 const proposal=c(['harmonia/vault-initialization-proposal/v1',p.idempotencyKey,p.device.id,p.device.signingPublicKey,p.device.receivingPublicKey,p.recoveryGeneration,p.recoverySigningPublicKey,p.recoveryReceivingPublicKey,p.trustRootSignature,envs]);
 const q=o.proof,proof=c(['harmonia/vault-initialize/v1',q.accountId,q.accountGeneration,q.loginTokenHash,q.challengeId,q.nonce,q.expiresAt,q.proposalHash]);
 return {proposal,proof};
}
test('原初始化双签独立冻结原根与唯一初始授权',()=>{
 const {proposal,proof}=initBytes(),o=v.originalInitialization;
 assert.equal(h(proposal),o.proof.proposalHash);
 assert.equal(h(c(['harmonia/recovery-initialization-anchor/v1',b64(proposal),b64(proof),o.deviceSignature,o.recoverySignature,'1'])),v.initializationHash);
 assert(verify(null,proof,pk(v.rootPin.SigningPublicKey),Buffer.from(o.deviceSignature,'base64url')));
 assert(verify(null,proof,pk(o.proposal.recoverySigningPublicKey),Buffer.from(o.recoverySignature,'base64url')));
 assert.equal(b64(sign(null,proof,sk(v.syntheticSeedsHex.rootEd))),o.deviceSignature);
 assert.equal(b64(sign(null,proof,sk(recoverySeed('oldRecovery','1')))),o.recoverySignature);
});
test('Go/Node25项过渡、全部引用集合与两签精确一致',()=>{
 for(const [name,hex,hash,authSeed,nextSeed] of [
 ['oldRecoveryTransition',v.transitionSigningHex,v.transitionHash,recoverySeed('oldRecovery','1'),recoverySeed('newRecovery','2')],
 ['allAdminTransition',v.allAdminSigningHex,v.allAdminHash,v.syntheticSeedsHex.managerEd,recoverySeed('newRecovery','2')],
 ['managerReanchor',v.reanchorSigningHex,v.reanchorHash,v.syntheticSeedsHex.managerEd,recoverySeed('thirdRecovery','3')],
 ]){
  const r=v[name],s=r.submission,t=s.transition,b=tb(t);assert.equal(JSON.parse(b.toString()).length,25);assert.equal(b.toString('hex'),hex);assert.equal(transitionRef(s),hash);assert.equal(r.sequence,Number(t.expectedSequence)+1);
  assert.equal(b64(sign(null,b,sk(authSeed))),s.authorizationSignature);assert.equal(b64(sign(null,b,sk(nextSeed))),s.newRecoverySignature);
  assert.equal(h(c(['harmonia/recovery-environment-manifest/v1',s.environmentManifest.map((x:any)=>[x.environmentId,x.keyVersion])])),t.environmentManifestHash);
  assert.equal(envelopeHash('harmonia/recovery-envelopes/v1',s.envelopes),t.envelopesHash);
  assert.equal(h(c(['harmonia/recovery-trust-root-ref/v1',b64(tr(s.newTrustRoot)),s.newTrustRoot.signature])),t.newTrustRootHash);
  assert(verify(null,tr(s.newTrustRoot),pk(t.newRecoverySigningPublicKey),Buffer.from(s.newTrustRoot.signature,'base64url')));
  if(t.authorizationKind==='all-environments-admin'){
   assert.equal(h(c(['harmonia/recovery-admin-authorities/v1',s.authoritySet.map((x:any)=>[x.environmentId,x.keyVersion,x.grantGeneration,x.expiresAt,x.authorityHash])])),t.authoritySetHash);
   assert.equal(evidenceHash(s.issuerEvidence),t.issuerEvidenceHash);assert.equal(s.authoritySet.length,s.environmentManifest.length);
  } else {assert.equal(t.authorizerDeviceId,'');assert.deepEqual(s.authoritySet,[]);assert.equal(s.issuerEvidence,null)}
  if(t.chainMode==='manager-reanchor'){
   const l=s.legacyState;assert.equal(h(c(['harmonia/recovery-legacy-state/v1',l.recoveryGeneration,l.recoverySigningPublicKey,l.recoveryReceivingPublicKey,b64(tr(l.trustRoot)),l.trustRoot.signature,l.rotations.map((x:any)=>[x.idempotencyKey,x.signingBytes,x.signature,String(x.sequence)])])),t.legacyStateHash);
   const legacy=Buffer.from(l.rotations[0].signingBytes,'base64url'),f=JSON.parse(legacy.toString());assert.equal(f.length,13);assert(verify(null,legacy,pk(f[9]),Buffer.from(l.rotations[0].signature,'base64url')));
   assert(!verify(null,b,pk(l.recoverySigningPublicKey),Buffer.from(s.authorizationSignature,'base64url')));
  }
 }
});
test('Go/Node18项显式恢复设备证书及用户选择和HPKE引用一致',()=>{
 const s=v.recoveredDevice.submission,e=s.enrollment,b=db(e);assert.equal(JSON.parse(b.toString()).length,18);assert.equal(s.certificateVersion,'4');assert.deepEqual(s.capabilities,['issuer-recovery-v1']);assert.equal(b.toString('hex'),v.deviceSigningHex);assert.equal(deviceRef(s),v.deviceHash);
 assert.equal(e.recoveryTransitionHash,v.transitionHash);assert.equal(v.recoveredDevice.sequence,Number(e.expectedSequence)+1);
 assert.equal(b64(sign(null,b,sk(recoverySeed('newRecovery','2')))),s.recoverySignature);assert.equal(b64(sign(null,b,sk(v.syntheticSeedsHex.deviceEd))),s.deviceSignature);
 assert.equal(h(c(['harmonia/recovered-device-rights/v1',s.selectedRights.map((x:any)=>[x.environmentId,x.keyVersion,x.role,x.expiresAt])])),e.selectedRightsHash);
 assert.equal(h(c(['harmonia/recovered-device-grants/v1',s.grants.map((g:any)=>[g.grant.environmentId,b64(grantSigningBytes(g.grant)),g.signature])])),e.grantsHash);
 assert.equal(envelopeHash('harmonia/recovered-device-envelopes/v1',s.envelopes),e.envelopesHash);assert.equal(evidenceHash(s.issuerEvidence),e.issuerEvidenceHash);
 assert.equal(s.selectedRights.length,1);assert.equal(s.selectedRights[0].environmentId,'environment-Y');assert.equal(s.grants[0].grant.envelope,s.envelopes[0].envelope);
 assert(verify(null,grantSigningBytes(s.grants[0].grant),pk(e.deviceSigningPublicKey),Buffer.from(s.grants[0].signature,'base64url')));
});
test('全部过渡和恢复设备标量替换不能沿用原签名',()=>{
 const s=v.oldRecoveryTransition.submission,bp=pk(s.transition.oldRecoverySigningPublicKey);
 for(const name of tf){const t=structuredClone(s.transition);t[name]+='x';assert(!verify(null,tb(t),bp,Buffer.from(s.authorizationSignature,'base64url')))}
 const d=v.recoveredDevice.submission,dp=pk(d.enrollment.deviceSigningPublicKey);
 for(const name of df){const e=structuredClone(d.enrollment);e[name]+='x';assert(!verify(null,db(e),dp,Buffer.from(d.deviceSignature,'base64url')))}
 const changed=structuredClone(s.transition);changed.authorizationKind='all-environments-admin';assert(!verify(null,tb(changed),bp,Buffer.from(s.authorizationSignature,'base64url')));
});
