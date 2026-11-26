/**
 * Trusted network egress. Data leaves ONLY through this function, so destination rules are enforced at the actual egress point:
 *  - the destination is re-normalized here and must equal the host the authorization service approved (no parser differences);
 *  - https only, default port only, no IP-literal hosts, no URL credentials;
 *  - DNS is resolved HERE; if ANY returned address is private, loopback, link-local, multicast, CGNAT, documentation or
 *    otherwise non-public, the transfer is refused (blocks rebinding tricks and internal-address SSRF);
 *  - the connection is pinned to the vetted IP (no second DNS lookup), with the original host used for SNI/Host;
 *  - redirects are never followed;
 *  - request size and time are bounded.
 *
 * It protects transfers made through the executor. It does not (and cannot) control other programs' network traffic.
 */
import { BlockList, isIP } from "node:net";
import { lookup } from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import { normalizeDestination } from "../shared/policy.js";

export class EgressRefusal extends Error {
  constructor(
    public code: "DESTINATION_INVALID" | "DESTINATION_MISMATCH" | "SCHEME_NOT_ALLOWED" | "IP_LITERAL" | "PORT_NOT_ALLOWED" | "PRIVATE_ADDRESS" | "DNS_FAILED" | "REDIRECT_REFUSED" | "TOO_LARGE" | "NETWORK_ERROR",
    message: string,
  ) {
    super(message);
    this.name = "EgressRefusal";
  }
}

const blocked = new BlockList();
for (const [net, p] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
  ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) blocked.addSubnet(net, p, "ipv4");
for (const [net, p] of [["::", 128], ["::1", 128], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8], ["2001:db8::", 32], ["2002::", 16], ["64:ff9b::", 96], ["100::", 64]] as const) blocked.addSubnet(net, p, "ipv6");

/** True only for globally routable unicast addresses. IPv4-mapped IPv6 is judged by its embedded IPv4 address. */
export function isPublicAddress(ip: string): boolean {
  const fam = isIP(ip);
  if (!fam) return false;
  if (fam === 6) {
    const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
    if (m) return isPublicAddress(m[1]);
    if (/^::ffff:/i.test(ip)) return false; // hex-form mapped addresses: refuse rather than parse
  }
  return !blocked.check(ip, fam === 4 ? "ipv4" : "ipv6");
}

export interface EgressOptions {
  /** Override DNS (tests use this to map names to a controlled receiver). */
  resolve?: (host: string) => Promise<string[]>;
  timeoutMs?: number;
  maxBytes?: number;
  /** TEST ONLY: permit loopback targets and plain http on a custom port so a local receiver can be used. Never set in production. */
  testReceiver?: { port: number };
}

export interface EgressResult {
  status: number;
  host: string;
  address: string;
  bytes: number;
}

export class ProtectedEgress {
  constructor(private opts: EgressOptions = {}) {}

  /** Validates the destination and resolves/vets DNS without sending anything. Also used as a pre-claim check. */
  async plan(destination: string, approvedHost: string): Promise<{ url: URL; host: string; address: string }> {
    const n = normalizeDestination(destination);
    if (!n.ok) throw new EgressRefusal("DESTINATION_INVALID", "Destination is not a valid http(s) URL without credentials");
    if (n.isIp) throw new EgressRefusal("IP_LITERAL", "IP-literal destinations are refused");
    if (n.host !== approvedHost) throw new EgressRefusal("DESTINATION_MISMATCH", "Destination host differs from the host that was authorized");
    const url = new URL(destination.includes("://") ? destination : `https://${destination}`);
    const test = this.opts.testReceiver;
    if (!test) {
      if (url.protocol !== "https:") throw new EgressRefusal("SCHEME_NOT_ALLOWED", "Only https destinations are allowed");
      if (url.port && url.port !== "443") throw new EgressRefusal("PORT_NOT_ALLOWED", "Only the default https port is allowed");
    }
    let addrs: string[];
    try {
      addrs = this.opts.resolve ? await this.opts.resolve(n.host) : (await lookup(n.host, { all: true, verbatim: true })).map((a) => a.address);
    } catch {
      throw new EgressRefusal("DNS_FAILED", "Destination could not be resolved");
    }
    if (addrs.length === 0) throw new EgressRefusal("DNS_FAILED", "Destination resolved to no address");
    // Test-receiver mode only relaxes the rule for addresses that are exactly loopback.
    const ok = (a: string) => isPublicAddress(a) || (test !== undefined && (a === "127.0.0.1" || a === "::1"));
    if (!addrs.every(ok)) throw new EgressRefusal("PRIVATE_ADDRESS", "Destination resolves to a non-public address");
    return { url, host: n.host, address: addrs[0] };
  }

  async send(input: { destination: string; approvedHost: string; body: Buffer; contentType?: string }): Promise<EgressResult> {
    const maxBytes = this.opts.maxBytes ?? 1024 * 1024;
    if (input.body.length > maxBytes) throw new EgressRefusal("TOO_LARGE", `Payload exceeds ${maxBytes} bytes`);
    const { url, host, address } = await this.plan(input.destination, input.approvedHost);
    const test = this.opts.testReceiver;
    const n = { host };

    return new Promise<EgressResult>((resolve, reject) => {
      const mod = test ? http : https;
      const req = mod.request(
        {
          host: address, // pinned: no further DNS lookup
          port: test ? test.port : 443,
          method: "POST",
          path: url.pathname + url.search,
          headers: { Host: n.host, "Content-Type": input.contentType ?? "application/octet-stream", "Content-Length": String(input.body.length) },
          ...(test ? {} : { servername: n.host, rejectUnauthorized: true }),
          timeout: this.opts.timeoutMs ?? 10_000,
        },
        (res) => {
          res.resume();
          const status = res.statusCode ?? 0;
          if (status >= 300 && status < 400) return reject(new EgressRefusal("REDIRECT_REFUSED", "Redirects are never followed"));
          res.on("end", () => resolve({ status, host: n.host, address, bytes: input.body.length }));
        },
      );
      req.on("timeout", () => req.destroy(new Error("timeout")));
      req.on("error", (e) => reject(new EgressRefusal("NETWORK_ERROR", `Transfer failed: ${e.message}`)));
      req.end(input.body);
    });
  }
}
