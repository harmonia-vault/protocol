import {createHash,createPrivateKey,createPublicKey,hkdfSync,sign,verify} from 'node:crypto';
import {grantSigningBytes} from '../typescript/wire.ts';
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
function cert(a:any,version:string,proofHash:string){const x=a.context;const f=['harmonia/device-enrollment/v'+version,a.pairingProfile,x.accountId,x.accountGeneration,x.sessionId,x.challengeNonce,x.expiresAt,x.initiatorDeviceId,x.initiatorSigningPublicKey,x.initiatorReceivingPublicKey,x.approverDeviceId,x.approverSigningPublicKey,x.approverReceivingPublicKey,a.transcriptHash,grhash(a.grants)];f.push(proofHash);return c(f)}
const tf=['accountId','accountGeneration','operationId','challengeId','nonce','expiresAt','sessionHash','expectedSequence','previousTransitionHash','oldRecoveryGeneration','oldRecoverySigningPublicKey','oldRecoveryReceivingPublicKey','newRecoveryGeneration','newRecoverySigningPublicKey','newRecoveryReceivingPublicKey','authorizationKind','authorizerDeviceId','environmentManifestHash','authoritySetHash','issuerEvidenceHash','envelopesHash','newTrustRootHash'];
const df=['accountId','accountGeneration','recoveryGeneration','recoveryTransitionHash','operationId','challengeId','nonce','expiresAt','restrictedSessionHash','expectedSequence','deviceId','deviceSigningPublicKey','deviceReceivingPublicKey','selectedRightsHash','grantsHash','issuerEvidenceHash','envelopesHash'];
const tr=(r:any,p:any)=>c(['harmonia/trust-root/v1',p.accountId,p.accountGeneration,r.rootDeviceId,r.rootSigningPublicKey,r.rootReceivingPublicKey,r.recoveryGeneration,r.recoverySigningPublicKey,r.recoveryReceivingPublicKey]);
const envelopeHash=(domain:string,rows:any[])=>h(c([domain,rows.map(e=>[e.environmentId,e.keyVersion,e.envelope])]));
function initBytes(o:any){
 const p=o.proposal;
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
 return c([p.profile,p.accountId,p.accountGeneration,p.initializationHash,[b64(tr(p.trustRoot,p)),p.trustRoot.signature],p.recoveryHeadHash,path(p.path),rows,targets,origins,branches,deps]);
}
const sourceBytes=(s:any)=>c(['harmonia/recovery-source/v1',s.kind,s.view.profile,b64(viewBytes(s.view))]);
function dagBytes(p:any){const {proposal,proof}=initBytes(p.initialization),anchor=h(c(['harmonia/recovery-initialization-anchor/v1',b64(proposal),b64(proof),p.initialization.deviceSignature,p.initialization.recoverySignature,'1']));const records=p.records.map(recordRow).sort((a:string[],b:string[])=>asc(a[0],b[0])||asc(a[1],b[1]));return c([p.profile,p.accountId,p.accountGeneration,[anchor,b64(proposal),b64(proof),p.initialization.deviceSignature,p.initialization.recoverySignature,'1'],h(sourceBytes(p.source)),records]);}

export { c, b64, h, sk, pk, gh, originBytes, oh, cert, tv, dv, recordRow, viewBytes, sourceBytes, dagBytes, envelopeHash };
