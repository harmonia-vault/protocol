import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash,createPublicKey,verify} from 'node:crypto';
const v=JSON.parse(readFileSync(new URL('../vectors/recovery-operation-resolution-v1.json',import.meta.url),'utf8'));
const c=(x:unknown)=>Buffer.from(JSON.stringify(x),'utf8');
const h=(x:unknown)=>createHash('sha256').update(c(x)).digest('hex');
const targetFields=(t:any)=>{const b=t.basis;return ['harmonia/recovery-operation-target/v1','1',t.profile,t.kind,t.accountId,t.accountGeneration,t.operationId,t.originalSessionHash,t.authorizationKind,t.deviceId,t.deviceSigningPublicKey,t.deviceReceivingPublicKey,t.stage,b.initializationHash,b.expectedSequence,b.recoveryGeneration,b.recoveryHeadHash,b.recoverySigningPublicKey,b.recoveryReceivingPublicKey,b.dependencyBundleHash,b.environmentManifestHash,t.declaredIntentHash,t.knownChallengeHash,t.declaredContentHash];};
const signingFields=(r:any,sessionHash:string)=>['harmonia/recovery-operation-resolution/v1',r.mode,sessionHash,h(targetFields(r.target))];
const pk=(pub:string)=>createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(pub,'base64url')]),format:'der',type:'spki'});
test('三阶段原target与当前受限session签名字节逐字节一致',()=>{
 for(const f of v.requests){assert.equal(c(targetFields(f.request.target)).toString('hex'),f.targetCanonicalHex);assert.equal(h(targetFields(f.request.target)),f.targetHash);assert.equal(c(signingFields(f.request,v.currentSessionHash)).toString('hex'),f.signingCanonicalHex);assert(verify(null,c(signingFields(f.request,v.currentSessionHash)),pk(f.request.target.deviceSigningPublicKey),Buffer.from(f.request.deviceSignature,'base64url')));}
 assert.equal(v.requests[0].request.target.stage,'intent');assert.equal(v.requests[0].request.target.knownChallengeHash,'');assert.equal(v.requests[1].request.target.declaredContentHash,'');assert.notEqual(v.requests[1].targetHash,v.requests[2].targetHash);
});
test('mode/current bearer/原账号基点双钥选择摘要全部绑定；签名不授予当前权限',()=>{
 const r=v.requests[2].request,key=pk(r.target.deviceSigningPublicKey),sig=Buffer.from(r.deviceSignature,'base64url');
 assert(!verify(null,c(signingFields({...r,mode:'query'},v.currentSessionHash)),key,sig));assert(!verify(null,c(signingFields(r,h(['different-current-session']))),key,sig));
 for(const field of ['accountId','accountGeneration','originalSessionHash','deviceReceivingPublicKey','declaredIntentHash','declaredContentHash']){const x=structuredClone(r);x.target[field]+='changed';assert(!verify(null,c(signingFields(x,v.currentSessionHash)),key,sig));}
 for(const field of Object.keys(r.target.basis)){const x=structuredClone(r);x.target.basis[field]+='changed';assert(!verify(null,c(signingFields(x,v.currentSessionHash)),key,sig));}
});
test('transition挑战规范摘要用确定字段，不序列化对象；old-recovery空Admin集固定',()=>{
 const x=v.transitionChallenge,t=x.challenge,initialization=v.transitionChallenge.challenge.dependencyBundle.initialization;
 // 原初始化/records的规范字节已由成熟DAG向量独立测试；本片摘要把它们作为已固定字节输入。
 assert.equal(x.emptyAdminHash,h(['harmonia/recovery-admin-authorities/v1',[]]));
 const manifest=h(['harmonia/recovery-environment-manifest/v1',t.environmentManifest.map((e:any)=>[e.environmentId,e.keyVersion])]);
 const fields=['harmonia/recovery-operation-challenge/v1','transition-v2',x.accountId,t.accountGeneration,t.operationId,t.challengeId,t.nonce,String(t.expiresAt),t.sessionHash,t.authorizationKind,t.authorizerDeviceId,t.expectedSequence,t.previousTransitionHash,t.oldRecoveryGeneration,t.oldRecoverySigningPublicKey,t.oldRecoveryReceivingPublicKey,manifest,x.emptyAdminHash,'',x.dependencyBasisHash];
 assert.equal(h(fields),x.challengeHash);assert(t.issuerEvidence===null&&t.authoritySet.length===0);assert.equal(initialization.sequence,1);
 const altered=[...fields];altered[4]='another-operation';assert.notEqual(h(altered),x.challengeHash);
});
test('三态响应字段明确，pending没有终态/接受凭证，closed不复用contentHash',()=>{
 const common=['version','profile','accountId','accountGeneration','kind','operationId','targetHash','state'];
 for(const [state,r] of Object.entries(v.receipts) as [string,any][]){const extra=state==='pending'?[]:state==='accepted'?['sequence','contentHash']:['sequence','observedChallengeHash'];assert.deepEqual(Object.keys(r).sort(),[...common,...extra].sort());assert.equal(r.state,state);assert.equal(r.profile,'harmonia-recovery-operation-resolution-v1');}
 assert.equal(v.receipts.closed.observedChallengeHash,null);assert.equal(v.receipts.accepted.contentHash,v.requests[2].request.target.declaredContentHash);
});
