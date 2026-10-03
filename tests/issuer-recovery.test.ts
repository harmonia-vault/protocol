import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash,createPrivateKey,createPublicKey,hkdfSync,sign,verify} from 'node:crypto';
import {grantSigningBytes} from '../typescript/wire.ts';
const fixture=JSON.parse(readFileSync(new URL('../vectors/issuer-recovery-v1.json',import.meta.url),'utf8'));
const v=fixture.recovery;
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

function recoveryProofBytes(p:any){
 const root=p.trustRoot;
 const path=(rows:any[])=>rows.map(n=>n.kind==='recovered'?['recovered',n.recoveryEnrollmentHash]:['paired',n.enrollment.certificateVersion,b64(cert(n.enrollment.approval,n.enrollment.certificateVersion,n.enrollment.issuerProofHash)),n.enrollment.approval.approverSignature,n.enrollment.approval.initiatorSignature]);
 const authorities=[...p.authorities].sort((a,b)=>{const x=a.grant.grant,y=b.grant.grant;for(const k of ['environmentId','subjectDeviceId'])if(x[k]!==y[k])return x[k]<y[k]?-1:1;return BigInt(x.grantGeneration)<BigInt(y.grantGeneration)?-1:BigInt(x.grantGeneration)>BigInt(y.grantGeneration)?1:0}).map(a=>[a.grant.grant.environmentId,a.grant.grant.subjectDeviceId,a.grant.grant.grantGeneration,b64(grantSigningBytes(a.grant.grant)),a.grant.signature,a.parentHash,a.originHash,a.previousGrantHash,a.recoveryEnrollmentHash]);
 const targets=[...p.targets].sort((a,b)=>a.environmentId<b.environmentId?-1:a.environmentId>b.environmentId?1:0).map(x=>[x.environmentId,x.authorityHash]);
 const origins=p.origins.map((s:any)=>[oh(s),b64(originBytes(s.origin)),s.signature]).sort((a:any,b:any)=>a[0]<b[0]?-1:a[0]>b[0]?1:0);
 const branches=p.identityPaths.map(path).sort((a:any,b:any)=>JSON.stringify(a)<JSON.stringify(b)?-1:JSON.stringify(a)>JSON.stringify(b)?1:0);
 const transitions=p.transitions.map((r:any)=>[transitionRef(r.submission),b64(tb(r.submission.transition)),r.submission.authorizationSignature,r.submission.newRecoverySignature,String(r.sequence)]).sort((a:any,b:any)=>a[0]<b[0]?-1:a[0]>b[0]?1:0);
 const devices=p.recoveredDevices.map((r:any)=>[deviceRef(r.submission),b64(db(r.submission.enrollment)),r.submission.recoverySignature,r.submission.deviceSignature,String(r.sequence)]).sort((a:any,b:any)=>a[0]<b[0]?-1:a[0]>b[0]?1:0);
 const {proposal,proof}=initBytes(),initial=['harmonia/recovery-initialization-anchor/v1',b64(proposal),b64(proof),p.initialization.deviceSignature,p.initialization.recoverySignature,'1'];
 return c(['harmonia/issuer-proof/v3',p.accountId,p.accountGeneration,[b64(tr(root)),root.signature],[h(c(initial)),b64(proposal),b64(proof),p.initialization.deviceSignature,p.initialization.recoverySignature,'1'],path(p.path),authorities,targets,origins,branches,transitions,devices]);
}
test('Go/Node proof3十二项和v4配对子设备签名精确互操作',()=>{
 const p=fixture.proof,b=recoveryProofBytes(p);assert.equal(JSON.parse(b.toString()).length,12);assert.equal(b.toString('hex'),fixture.canonicalHex);assert.equal(h(b),fixture.hash);
 const n=p.path[1].enrollment,cb=cert(n.approval,'4',n.issuerProofHash);assert.equal(cb.toString('hex'),fixture.certificateSigningHex);
 assert.equal(b64(sign(null,cb,sk(v.syntheticSeedsHex.deviceEd))),n.approval.approverSignature);assert.equal(b64(sign(null,cb,sk(fixture.syntheticChildEdSeedHex))),n.approval.initiatorSignature);
 assert(verify(null,cb,pk(n.approval.context.approverSigningPublicKey),Buffer.from(n.approval.approverSignature,'base64url')));
 assert(!verify(null,cert(n.approval,'3',n.issuerProofHash),pk(n.approval.context.approverSigningPublicKey),Buffer.from(n.approval.approverSignature,'base64url')));
});
test('恢复来源仅选定Y权限，原根不移动，子设备由明确Admin父节点签发',()=>{
 const p=fixture.proof,origin=p.path[0],r=p.recoveredDevices[0],certNode=p.path[1].enrollment,byHash=new Map(p.authorities.map((x:any)=>[gh(x.grant),x]));
 assert.equal(origin.kind,'recovered');assert.equal(origin.recoveryEnrollmentHash,deviceRef(r.submission));assert.equal(p.trustRoot.rootDeviceId,v.rootPin.DeviceID);assert.equal(p.trustRoot.rootSigningPublicKey,v.rootPin.SigningPublicKey);
 const recovered:any=byHash.get(gh(r.submission.grants[0]));assert.equal(recovered.recoveryEnrollmentHash,origin.recoveryEnrollmentHash);assert.equal(recovered.parentHash,'');assert.equal(recovered.originHash,'');assert.equal(recovered.previousGrantHash,'');assert.equal(recovered.grant.grant.environmentId,'environment-Y');assert.equal(recovered.grant.grant.role,'admin');
 const child:any=byHash.get(gh(certNode.approval.grants[0]));assert.equal(child.parentHash,gh(recovered.grant));assert.equal(child.recoveryEnrollmentHash,'');assert.equal(child.grant.grant.role,'ro');assert.equal(child.grant.grant.environmentId,'environment-Y');
 for(const field of ['path','transitions','recoveredDevices']){const q=structuredClone(p);q[field]=[];assert.notEqual(h(recoveryProofBytes(q)),fixture.hash)}
});
