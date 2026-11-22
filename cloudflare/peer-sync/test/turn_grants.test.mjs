import test from "node:test";
import assert from "node:assert/strict";
import {createTurnIssuer, TurnGrantError} from "../src/turn_grants.mjs";

const secret = "test_only_secret_".repeat(4);
const request = {test_request: "not a real credential"};
const validProof = (purpose, overrides = {}) => ({
  purpose, authenticated: true, active_device: true, revocation_checked: true,
  key_epoch: 1, verified_at_ms: Date.now(), ...overrides,
});
const granted = {
  iceServers: [
    {urls: ["stun:stun.cloudflare.com:3478"]},
    {urls: ["turn:turn.cloudflare.com:3478?transport=udp",
      "turns:turn.cloudflare.com:443?transport=tcp"],
     username: "ephemeral_username", credential: "ephemeral_credential"},
  ],
};
const fails = (code) => (error) =>
  error instanceof TurnGrantError && error.code === code;

test("long-lived key, official verifier and fetch are mandatory", () => {
  assert.throws(() => createTurnIssuer(), fails("turn_not_configured"));
  assert.throws(() => createTurnIssuer({turnKeyId:"../../evil", turnApiToken:secret,
    verifyDeviceRequest:async()=>true}), fails("turn_not_configured"));
  assert.throws(() => createTurnIssuer({turnKeyId:"turn_key",turnApiToken:"short",
    verifyDeviceRequest:async()=>true}), fails("turn_not_configured"));
});

test("revoked, stale or wrong-purpose requests never request credentials", async () => {
  for (const changes of [
    {active_device:false}, {revocation_checked:false},
    {verified_at_ms:Date.now()-90_000}, {purpose:"text_cache.read"},
    {authenticated:false},
  ]) {
    let calls = 0;
    const issuer = createTurnIssuer({
      turnKeyId:"turn_key", turnApiToken:secret,
      verifyDeviceRequest:async(_request, args) => validProof(args.purpose,changes),
      fetchImpl:async()=> { calls++; throw Error("network should not be called"); },
    });
    await assert.rejects(issuer.issue(request), fails("turn_authority_unavailable"));
    assert.equal(calls,0);
  }
});

test("authorized issuer uses only Cloudflare TURN endpoint and fixed short TTL", async () => {
  const calls=[];
  const issuer=createTurnIssuer({
    turnKeyId:"turn_key",turnApiToken:secret,
    verifyDeviceRequest:async(_request,args)=>validProof(args.purpose),
    fetchImpl:async(url,options)=>{
      calls.push({url,options});
      return {status:201,json:async()=>granted};
    },
  });
  const result=await issuer.issue(request);
  assert.equal(calls.length,1);
  assert.equal(calls[0].url,
    "https://rtc.live.cloudflare.com/v1/turn/keys/turn_key/credentials/generate-ice-servers");
  assert.equal(calls[0].options.method,"POST");
  assert.deepEqual(JSON.parse(calls[0].options.body),{ttl:900});
  assert.equal(calls[0].options.headers.Authorization,"Bearer "+secret);
  assert.deepEqual(result.iceServers,granted.iceServers);
  assert.equal(result.cache_control,"no-store");
  assert.equal(result.ttl_seconds,900);
  assert.equal(JSON.stringify(result).includes(secret),false);
});

test("upstream errors, hostile URLs and malformed grants fail without secret leakage", async () => {
  for(const payload of [
    {iceServers:[]},
    {iceServers:[{urls:["stun:stun.cloudflare.com:3478"]}]},
    {iceServers:[{urls:["turn:evil.example:443?transport=tcp"],
      username:"u",credential:"c"}]},
    {iceServers:[{urls:["turn:turn.cloudflare.com:443?transport=tcp"],
      username:"u",credential:"bad credential"}]},
    {iceServers:[{urls:["turn:turn.cloudflare.com:443?transport=tcp"]}]},
  ]) {
    const issuer=createTurnIssuer({
      turnKeyId:"turn_key",turnApiToken:secret,
      verifyDeviceRequest:async(_r,args)=>validProof(args.purpose),
      fetchImpl:async()=>({status:201,json:async()=>payload}),
    });
    await assert.rejects(issuer.issue(request),(err)=>
      fails("turn_unavailable")(err) && !err.message.includes(secret));
  }
  const denied=createTurnIssuer({
    turnKeyId:"turn_key",turnApiToken:secret,
    verifyDeviceRequest:async(_r,args)=>validProof(args.purpose),
    fetchImpl:async()=>({status:401,json:async()=>({api_token:secret})}),
  });
  await assert.rejects(denied.issue(request), fails("turn_unavailable"));
});
