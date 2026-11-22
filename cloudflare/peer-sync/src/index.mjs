import {DurableObject} from "cloudflare:workers";

// Deliberately sealed bootstrap. Live sync MUST NOT be admitted before the
// official Shared Auth verifier, enrollment/revocation state, replay controls,
// per-account D1 transaction ownership, and device signature checks are wired.
const locked = () => Response.json(
  {error: "not_activated", message: "Cloudflare peer sync is not production-enabled"},
  {status: 503, headers: {"Cache-Control": "no-store"}}
);

export class PeerRoom extends DurableObject {
  async fetch(_request) {
    return locked(); // No unauthenticated websocket or message relay.
  }
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/healthz") {
      return Response.json(
        {service: "cliptown-peer-sync", ready: false, accepts_clipboard_data: false},
        {headers: {"Cache-Control": "no-store"}}
      );
    }
    return locked();
  }
};
