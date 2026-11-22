import test from "node:test";
import assert from "node:assert/strict";
import {
  createD1NonceStore, DELETE_EXPIRED_NONCES_SQL,
  CONSUME_DEVICE_NONCE_SQL, MAX_ACTIVE_NONCES_PER_ACCOUNT,
} from "../src/device_nonces.mjs";

class StubD1 {
  constructor() { this.calls=[]; this.changes=1; this.fails=false; }
  prepare(sql) {
    return {bind:(...params)=>({sql,params})};
  }
  async batch(statements){
    this.calls.push(statements);
    if(this.fails) throw new Error("sensitive D1 backend error");
    return [
      {success:true,meta:{changes:0}},
      {success:true,meta:{changes:this.changes}},
    ];
  }
}
const entry=()=>({
  account_id:"account_a",device_id:"device_a",
  nonce:"A".repeat(26),expires_at_ms:Date.now()+30_000,
});

test("nonces cannot be consumed without configured D1",()=>{
  assert.throws(()=>createD1NonceStore(null));
  assert.throws(()=>createD1NonceStore({prepare(){}}));
});

test("atomic bounded nonce store binds authenticated account and device",async()=>{
  const db=new StubD1();
  const consume=createD1NonceStore(db);
  assert.equal(await consume(entry()),true);
  assert.equal(db.calls.length,1);
  assert.equal(db.calls[0][0].sql,DELETE_EXPIRED_NONCES_SQL);
  assert.equal(db.calls[0][1].sql,CONSUME_DEVICE_NONCE_SQL);
  assert.equal(db.calls[0][0].params[0],"account_a");
  assert.deepEqual(db.calls[0][1].params.slice(0,3),
    ["account_a","device_a","A".repeat(26)]);
  assert.equal(db.calls[0][1].params[4],"account_a");
  assert.equal(MAX_ACTIVE_NONCES_PER_ACCOUNT,1024);
});

test("duplicate, budget exhausted, and provider errors deny",async()=>{
  const db=new StubD1();
  const consume=createD1NonceStore(db);
  db.changes=0;
  assert.equal(await consume(entry()),false);
  db.changes=2;
  assert.equal(await consume(entry()),false);
  db.fails=true;
  assert.equal(await consume(entry()),false);
});

test("invalid account, device, expiry and nonce fail without D1 access",async()=>{
  const db=new StubD1();
  const consume=createD1NonceStore(db);
  for(const override of [
    {account_id:"bad account"},{device_id:"../../bad"},
    {nonce:"short"},{nonce:"A".repeat(87)},
    {expires_at_ms:Date.now()-1},
    {expires_at_ms:Date.now()+300_000},
    {expires_at_ms:Number.MAX_SAFE_INTEGER+1},
  ])assert.equal(await consume({...entry(),...override}),false);
  assert.equal(db.calls.length,0);
});
