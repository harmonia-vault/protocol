import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash,createPrivateKey,createPublicKey,hkdfSync,sign,verify} from 'node:crypto';
import {grantSigningBytes} from '../typescript/wire.ts';
const fixture=JSON.parse(readFileSync(new URL('../vectors/recovery-dag-v1.json',import.meta.url),'utf8'));
const v={rootPin:fixture.rootPin,originalInitialization:fixture.proof.initialization};
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

const asc=(a:string,b:string)=>a<b?-1:a>b?1:0;
const tv=(x:any,ver:string)=>c(['harmonia/recovery-authority-transition/v'+ver,...tf.map(k=>x[k])]);
const dv=(x:any,ver:string)=>c(['harmonia/recovered-device-enrollment/v'+ver,...df.map(k=>x[k])]);
function recordRow(r:any){const s=r.record.submission,ver=r.kind.slice(-1),transition=r.kind.startsWith('transition');const bytes=transition?tv(s.transition,ver):dv(s.enrollment,ver),sig1=transition?s.authorizationSignature:s.recoverySignature,sig2=transition?s.newRecoverySignature:s.deviceSignature;const ref=h(c([transition?'harmonia/recovery-authority-transition-ref/v'+ver:'harmonia/recovered-device-enrollment-ref/v'+ver,b64(bytes),sig1,sig2]));return [r.kind,ref,b64(bytes),sig1,sig2,String(r.record.sequence)];}
function viewBytes(p:any){
 const path=(ps:any[])=>ps.map(n=>n.kind==='recovered'?['recovered',n.recoveryEnrollmentHash]:['paired',n.enrollment.certificateVersion,b64(cert(n.enrollment.approval,n.enrollment.certificateVersion,n.enrollment.issuerProofHash)),n.enrollment.approval.approverSignature,n.enrollment.approval.initiatorSignature]);
 const rows=[...p.authorities].sort((a,b)=>{const x=a.grant.grant,y=b.grant.grant;for(const k of ['environmentId','subjectDeviceId'])if(x[k]!==y[k])return asc(x[k],y[k]);return BigInt(x.grantGeneration)<BigInt(y.grantGeneration)?-1:BigInt(x.grantGeneration)>BigInt(y.grantGeneration)?1:0}).map(a=>[a.grant.grant.environmentId,a.grant.grant.subjectDeviceId,a.grant.grant.grantGeneration,b64(grantSigningBytes(a.grant.grant)),a.grant.signature,a.parentHash,a.originHash,a.previousGrantHash,a.recoveryEnrollmentHash]);
 const targets=[...p.targets].sort((a,b)=>asc(a.environmentId,b.environmentId)).map(t=>[t.environmentId,t.authorityHash]);
 const origins=p.origins.map((s:any)=>[oh(s),b64(originBytes(s.origin)),s.signature]).sort((a:string[],b:string[])=>asc(a[0],b[0]));
 const branches=p.identityPaths.map(path).sort((a:any,b:any)=>asc(JSON.stringify(a),JSON.stringify(b)));
 const deps=[...p.dependencies].sort((a,b)=>asc(a.kind,b.kind)||asc(a.referenceHash,b.referenceHash)).map(x=>[x.kind,x.referenceHash]);
 return c([p.profile,p.accountId,p.accountGeneration,p.initializationHash,[b64(tr(p.trustRoot)),p.trustRoot.signature],p.recoveryHeadHash,path(p.path),rows,targets,origins,branches,deps]);
}
const sourceBytes=(s:any)=>c(['harmonia/recovery-source/v1',s.kind,s.kind==='proof2'?s.proof.profile:s.view.profile,b64(s.kind==='proof2'?proofBytes(s.proof):viewBytes(s.view))]);
function dagBytes(p:any){const {proposal,proof}=initBytes(),anchor=h(c(['harmonia/recovery-initialization-anchor/v1',b64(proposal),b64(proof),p.initialization.deviceSignature,p.initialization.recoverySignature,'1']));const records=p.records.map(recordRow).sort((a:string[],b:string[])=>asc(a[0],b[0])||asc(a[1],b[1]));return c([p.profile,p.accountId,p.accountGeneration,[anchor,b64(proposal),b64(proof),p.initialization.deviceSignature,p.initialization.recoverySignature,'1'],h(sourceBytes(p.source)),records]);}
test('Go/Node平坦Proof4、Source12和新25/18/16签名域逐字节一致',()=>{
 const p=fixture.proof,b=dagBytes(p);assert.equal(b.toString('hex'),fixture.canonicalHex);assert.equal(h(b),fixture.hash);assert.equal(JSON.parse(b.toString()).length,6);assert.equal(JSON.parse(viewBytes(p.source.view).toString()).length,12);
 const t=p.records.find((r:any)=>r.kind==='transition-v2'&&r.record.submission.transition.authorizationKind==='all-environments-admin').record.submission;
 const d=p.records.find((r:any)=>r.kind==='recovered-v2').record.submission;
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
