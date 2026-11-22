import test from "node:test";
import assert from "node:assert/strict";
import {createDeviceAuthorization, DeviceAuthError} from "../src/device_authorization.mjs";

const PAIR = await crypto.subtle.generateKey({name:"Ed25519"},true,["sign","verify"]);
const PUBLIC_JWK = await crypto.subtle.exportKey("jwk",PAIR.publicKey);
const TOKEN = "test_only_bearer_token_0123456789";
const DIGEST = "a".repeat(64);
const DEFAULT_AUTH = {
  active:true,sub:"account_a",iss:"https://auth.example/issuer",
  aud:"cliptown_sync",tenant_id:"tenant_a",application_id:"cliptown",
  actor_kind:"user",parent_jti:null,exp:Math.floor(Date.now()/1000)+3600,
  scope:"cliptown:sync:text:write cliptown:sync:text:read",
};
const DEFAULT_DEVICE = {
  active:true,revoked:false,account_id:"account_a",device_id:"device_a",
  key_epoch:7,revocation_epoch:3,enrollment_verified:true,
  public_key_jwk:PUBLIC_JWK,
};
const DEFAULT_OPTIONS = {
  audience:"cliptown_sync",issuer:"https://auth.example/issuer",
  tenantId:"tenant_a",applicationId:"cliptown",
};
const b64 = (bytes) => Buffer.from(bytes).toString("base64url");
const canonical = (proof) => new TextEncoder().encode(JSON.stringify([
  "cliptown.device_auth.v1","account_a","tenant_a","cliptown",
  proof.purpose,proof.device_id,proof.envelope_id,
  proof.ciphertext_digest,proof.media_kind,proof.device_sequence,
  proof.key_epoch,proof.revocation_epoch,proof.issued_at_ms,
  proof.expires_at_ms,proof.nonce,
]));
async function signedProof(purpose="text_cache.write",overrides={}) {
  const now=Date.now();
  const proof={
    protocol:"cliptown.device_auth.v1",purpose,device_id:"device_a",
    envelope_id:purpose==="text_cache.write"?"clip_1":"",
    ciphertext_digest:purpose==="text_cache.write"?DIGEST:"",
    media_kind:purpose==="text_cache.write"?"text":"none",
    device_sequence:purpose==="text_cache.write"?1:0,
    key_epoch:7,revocation_epoch:3,issued_at_ms:now-1000,
    expires_at_ms:now+30_000,nonce:b64(crypto.getRandomValues(new Uint8Array(20))),
    ...overrides,
  };
  proof.signature=b64(await crypto.subtle.sign(
    {name:"Ed25519"},PAIR.privateKey,canonical(proof)));
  return proof;
}
const req = (proof,token=TOKEN) => new Request(
  "https://cliptown.test/internal",
  {headers:{authorization:"Bearer "+token,
    "x-cliptown-device-proof":b64(new TextEncoder().encode(JSON.stringify(proof)))}}
);
const denies = (error) => error instanceof DeviceAuthError &&
  error.message === "device_authorization_denied";
const context=(purpose)=>purpose==="text_cache.write"?
  {purpose,envelope_id:"clip_1",digest:DIGEST}:{purpose};

function configured({
  auth=DEFAULT_AUTH, device=DEFAULT_DEVICE,
  onIntrospect=()=>{}, onLookup=()=>{}, consumeNonce,
}={}) {
  const seen=new Set();
  const client={introspect:async(token,audience,scopes)=>{
    onIntrospect(token,audience,scopes);
    return auth;
  }};
  const lookup=async(args)=>{onLookup(args);return device;};
  const nonces=consumeNonce??(async({account_id,device_id,nonce})=>{
    const key=JSON.stringify([account_id,device_id,nonce]);
    if(seen.has(key))return false;
    seen.add(key);
    return true;
  });
  return createDeviceAuthorization({
    sharedAuthClient:client,resolveEnrolledDevice:lookup,
    consumeNonce:nonces,...DEFAULT_OPTIONS,
  });
}

test("fails closed without official introspection, directory, nonce or configuration",()=>{
  for(const key of ["sharedAuthClient","resolveEnrolledDevice","consumeNonce",
    "audience","issuer","tenantId","applicationId"]){
    const options={
      sharedAuthClient:{introspect:async()=>DEFAULT_AUTH},
      resolveEnrolledDevice:async()=>DEFAULT_DEVICE,
      consumeNonce:async()=>true,...DEFAULT_OPTIONS,[key]:null,
    };
    assert.throws(()=>createDeviceAuthorization(options),denies);
  }
});

test("valid Ed25519 proof binds account, purpose, signed text kind and sequence",async()=>{
  let introspection=null,roster=null;
  const verify=configured({
    onIntrospect:(...args)=>{introspection=args},
    onLookup:(args)=>{roster=args},
  });
  const proof=await signedProof();
  const result=await verify(req(proof),context("text_cache.write"));
  assert.deepEqual(introspection,[TOKEN,"cliptown_sync",
    ["cliptown:sync:text:write"]]);
  assert.deepEqual(roster,{account_id:"account_a",device_id:"device_a",
    tenant_id:"tenant_a",application_id:"cliptown"});
  assert.equal(result.account_id,"account_a");
  assert.equal(result.device_id,"device_a");
  assert.equal(result.verified_device_sequence,1);
  assert.equal(result.verified_clip_kind,"text");
  assert.equal(result.signature_verified,true);
  assert.equal(result.revocation_checked,true);
});

test("fresh read requires independent one-use signed proof and verified scope",async()=>{
  const verify=configured();
  const proof=await signedProof("text_cache.read");
  const grant=await verify(req(proof),context("text_cache.read"));
  assert.equal(grant.purpose,"text_cache.read");
  assert.equal(grant.verified_device_sequence,0);
  await assert.rejects(verify(req(proof),context("text_cache.read")),denies);
});

test("modified signed digest, sequence, device and app cannot bypass signature",async()=>{
  const verify=configured();
  const proof=await signedProof();
  for(const [field,value] of [
    ["device_sequence",2],["key_epoch",8],["device_id","device_b"],
    ["ciphertext_digest","b".repeat(64)],["expires_at_ms",proof.expires_at_ms+1],
  ]){
    const altered={...proof,[field]:value};
    await assert.rejects(verify(req(altered),context("text_cache.write")),denies);
  }
});

test("signed file kind, wrong digest and invalid scope all deny",async()=>{
  const verify=configured();
  await assert.rejects(verify(req(await signedProof("text_cache.write",
    {media_kind:"file"})),context("text_cache.write")),denies);
  const proof=await signedProof();
  await assert.rejects(verify(req(proof),{purpose:"text_cache.write",
    envelope_id:"clip_1",digest:"b".repeat(64)}),denies);
  const noScope=configured({auth:{...DEFAULT_AUTH,scope:"other:permission"}});
  await assert.rejects(noScope(req(await signedProof()),
    context("text_cache.write")),denies);
});

test("revocation, cross-account membership, tenant and issuer are authoritative",async()=>{
  for(const auth of [
    {...DEFAULT_AUTH,active:false},{...DEFAULT_AUTH,sub:"account_b"},
    {...DEFAULT_AUTH,tenant_id:"tenant_b"},
    {...DEFAULT_AUTH,application_id:"other_app"},
    {...DEFAULT_AUTH,iss:"https://evil.example/"},
    {...DEFAULT_AUTH,aud:"some_other_api"},
    {...DEFAULT_AUTH,actor_kind:"service"},
    {...DEFAULT_AUTH,parent_jti:"delegated_jti"},
    {...DEFAULT_AUTH,exp:1},
  ]){
    const verify=configured({auth});
    await assert.rejects(verify(req(await signedProof()),
      context("text_cache.write")),denies);
  }
  for(const device of [
    {...DEFAULT_DEVICE,active:false},
    {...DEFAULT_DEVICE,revoked:true},
    {...DEFAULT_DEVICE,account_id:"account_b"},
    {...DEFAULT_DEVICE,key_epoch:6},
    {...DEFAULT_DEVICE,revocation_epoch:2},
    {...DEFAULT_DEVICE,enrollment_verified:false},
  ]){
    const verify=configured({device});
    await assert.rejects(verify(req(await signedProof()),
      context("text_cache.write")),denies);
  }
});

test("nonce store or official authority outage denies, no permissive fallback",async()=>{
  const proof=await signedProof();
  const noNonce=configured({consumeNonce:async()=>false});
  await assert.rejects(noNonce(req(proof),context("text_cache.write")),denies);
  const crashedNonce=configured({consumeNonce:async()=>{
    throw new Error("secret backend trace 123");
  }});
  await assert.rejects(crashedNonce(req(proof),context("text_cache.write")),
    (error)=>denies(error)&&!error.message.includes("secret"));
  const crashedAuth=createDeviceAuthorization({
    sharedAuthClient:{introspect:async()=>{throw new Error("token leak");}},
    resolveEnrolledDevice:async()=>DEFAULT_DEVICE,
    consumeNonce:async()=>true,...DEFAULT_OPTIONS,
  });
  await assert.rejects(crashedAuth(req(proof),context("text_cache.write")),
    (error)=>denies(error)&&!error.message.includes("token"));
});

test("expired, future, malformed or unknown fields fail before identity lookup",async()=>{
  let introspections=0;
  const verify=configured({onIntrospect:()=>{introspections++}});
  const now=Date.now();
  for(const overrides of [
    {issued_at_ms:now-150_000,expires_at_ms:now-30_000},
    {issued_at_ms:now+60_000,expires_at_ms:now+70_000},
    {expires_at_ms:now-1},{device_sequence:0},
    {device_sequence:9007199254740991},
    {nonce:"../invalid"}, {protocol:"unknown"},
  ]){
    await assert.rejects(verify(req(await signedProof("text_cache.write",
      overrides)),context("text_cache.write")),denies);
  }
  const unknown=await signedProof();
  unknown.access_token="forbidden";
  await assert.rejects(verify(req(unknown),context("text_cache.write")),denies);
  assert.equal(introspections,0);
});
