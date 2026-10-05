#!/usr/bin/env node
// SNI relay for home deployments — the data plane of contrib/home/relay/DESIGN.md.
//
// Listens on RELAY_LISTEN_IP:443 (a second private IP on the LAN interface), reads the TLS
// ClientHello's SNI, and pipes the TCP flow through the egress proxy (HTTP CONNECT). TLS is never
// terminated: certificates and secrets stay end to end between the client and the real server.
// The relay reports a self-check to the DoH server (/admin/relay-health); when it stops reporting,
// the server withdraws the DNS override and clients fall back to the direct path.
//
// Zero dependencies beyond Node's builtins. Runs as its own systemd unit (relay.service) reading
// /etc/edge-smart-doh/relay.env — deliberately NOT the main env: this process needs none of the
// resolver configuration and as few secrets as possible.

import net from "node:net";
import tls from "node:tls";

// ---------------------------------------------------------------- configuration

function required(name) {
  const value = process.env[name];
  if (!value) {
    console.error(JSON.stringify({ event: "missing_config", name }));
    process.exit(1);
  }
  return value;
}

function integer(name, fallback, minimum, maximum) {
  const parsed = Number.parseInt(process.env[name] ?? "", 10);
  return Number.isFinite(parsed) ? Math.max(minimum, Math.min(maximum, parsed)) : fallback;
}

const LISTEN_IP = required("RELAY_LISTEN_IP");
const LISTEN_PORT = integer("RELAY_LISTEN_PORT", 443, 1, 65535);
const [PROXY_HOST, PROXY_PORT_RAW] = required("RELAY_PROXY").split(":");
const PROXY_PORT = Number.parseInt(PROXY_PORT_RAW, 10);
const DOMAINS = (process.env.RELAY_DOMAINS ?? "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
const EXCLUDE = (process.env.RELAY_EXCLUDE_DOMAINS ?? "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
const ADMIN_URL = process.env.RELAY_ADMIN_URL || "http://127.0.0.1:8787";
const ADMIN_TOKEN = process.env.RELAY_ADMIN_TOKEN ?? "";
const REPORT_TTL_SECONDS = integer("RELAY_REPORT_TTL", 120, 30, 3600); // server withdraws ~3 missed reports later
const CHECK_INTERVAL_SECONDS = integer("RELAY_CHECK_INTERVAL", 30, 5, 600);
const SELF_CHECK_HOST = process.env.RELAY_SELF_CHECK_HOST || "github.com";
const MAX_CONNECTIONS = integer("RELAY_MAX_CONNECTIONS", 512, 1, 65536);
const PEEK_TIMEOUT_MS = integer("RELAY_PEEK_TIMEOUT", 3000, 500, 30000);
const IDLE_TIMEOUT_MS = integer("RELAY_IDLE_TIMEOUT", 30000, 1000, 3600000);
const DEBUG = process.env.RELAY_DEBUG === "1";

for (const [name, value] of [["RELAY_PROXY_PORT", PROXY_PORT], ["RELAY_LISTEN_PORT", LISTEN_PORT]]) {
  if (!Number.isFinite(value)) {
    console.error(JSON.stringify({ event: "invalid_config", name }));
    process.exit(1);
  }
}

function log(event, fields = {}) {
  if (DEBUG) console.log(JSON.stringify({ event, ...fields }));
}

// ---------------------------------------------------------------- name matching
// Same semantics as the server's domainMatches (src/dns/ecs.ts): exact, or `*.`/leading-dot
// suffix at a dot boundary (which also covers the bare domain).

function matches(name, pattern) {
  const n = name.toLowerCase().replace(/\.$/, "");
  const p = pattern.replace(/^\*\./, ".");
  return p.startsWith(".") ? n.endsWith(p) || n === p.slice(1) : n === p;
}

function relayedName(name) {
  return !EXCLUDE.some((pattern) => matches(name, pattern)) && DOMAINS.some((pattern) => matches(name, pattern));
}

// ---------------------------------------------------------------- ClientHello SNI

function sniFromClientHello(buf) {
  try {
    if (buf.length < 5) return undefined; // not enough of the record header yet
    if (buf[0] !== 0x16) return null; // not a TLS handshake record: refuse immediately
    const recordLength = buf.readUInt16BE(3);
    if (buf.length < 5 + recordLength) return undefined; // incomplete record: wait for more bytes
    let o = 5; // handshake header
    if (buf[o] !== 0x01) return undefined; // not ClientHello
    o += 4;
    o += 2 + 32; // client version + random
    const sessionIdLength = buf[o];
    o += 1 + sessionIdLength;
    const cipherLength = buf.readUInt16BE(o);
    o += 2 + cipherLength;
    const compressionLength = buf[o];
    o += 1 + compressionLength;
    const extensionsEnd = o + 2 + buf.readUInt16BE(o);
    o += 2;
    while (o + 4 <= extensionsEnd) {
      const type = buf.readUInt16BE(o);
      const length = buf.readUInt16BE(o + 2);
      o += 4;
      if (type === 0x0000) {
        const nameLength = buf.readUInt16BE(o + 3);
        return buf.toString("ascii", o + 5, o + 5 + nameLength);
      }
      o += length;
    }
  } catch {
    return null; // malformed: give up on this connection
  }
  return null; // complete ClientHello without an SNI
}

// ---------------------------------------------------------------- proxy dialing

function connectViaProxy(targetHost, targetPort, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(PROXY_PORT, PROXY_HOST);
    const fail = (error) => {
      socket.destroy();
      reject(error);
    };
    socket.setTimeout(timeoutMs, () => fail(new Error("proxy connect timeout")));
    socket.once("error", fail);
    socket.once("connect", () => {
      socket.write(`CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n\r\n`);
      let header = Buffer.alloc(0);
      const onData = (chunk) => {
        header = Buffer.concat([header, chunk]);
        const end = header.indexOf("\r\n\r\n");
        if (end === -1) {
          if (header.length > 8192) fail(new Error("proxy response header too long"));
          return;
        }
        socket.off("data", onData);
        socket.off("error", fail);
        socket.setTimeout(0);
        const statusLine = header.toString("ascii", 0, header.indexOf("\r\n"));
        if (!/\s2\d\d\s/.test(` ${statusLine} `)) {
          fail(new Error(`proxy CONNECT refused: ${statusLine}`));
          return;
        }
        // Pause until the pipes are attached in handle(): data arriving between the CONNECT
        // response and the pipe() calls (the server's first flight) would otherwise be dropped.
        socket.pause();
        resolve({ socket, buffered: header.subarray(end + 4) });
      };
      socket.on("data", onData);
    });
  });
}

// ---------------------------------------------------------------- measured pool
// The DoH server knows the measured IPs (github/site pools); the relay dials them by address so its
// own connections can never loop back through the DNS override. A relayed name's /dns-query answer
// IS the relay IP, which is exactly why this side channel exists (DESIGN.md §3.3).

const poolCache = new Map(); // host → { ips, expiresAt }

async function poolFor(name) {
  if (!ADMIN_TOKEN) return [];
  const cached = poolCache.get(name);
  if (cached && cached.expiresAt > Date.now()) return cached.ips;
  try {
    const response = await fetch(`${ADMIN_URL}/admin/pool?name=${encodeURIComponent(name)}`, { headers: { Authorization: `Bearer ${ADMIN_TOKEN}` } });
    if (response.ok) {
      const body = await response.json();
      const ips = Array.isArray(body.pool) ? body.pool.filter((ip) => /^\d+\.\d+\.\d+\.\d+$/.test(ip)).slice(0, 2) : [];
      poolCache.set(name, { ips, expiresAt: Date.now() + 60_000 });
      return ips;
    }
  } catch (error) {
    log("pool_fetch_error", { name, error: String(error) });
  }
  return [];
}

// ---------------------------------------------------------------- forwarding

const server = net.createServer((client) => {
  if (server.connections > MAX_CONNECTIONS) {
    client.destroy();
    return;
  }
  client.setTimeout(IDLE_TIMEOUT_MS, () => client.destroy());

  let buffered = Buffer.alloc(0);
  const peekTimer = setTimeout(() => client.destroy(), PEEK_TIMEOUT_MS);

  client.on("data", function onFirstData(chunk) {
    buffered = Buffer.concat([buffered, chunk]);
    if (buffered.length > 65536) {
      client.destroy();
      return;
    }
    const sni = sniFromClientHello(buffered);
    if (sni === undefined) return; // need more bytes for the full ClientHello
    client.off("data", onFirstData);
    clearTimeout(peekTimer);
    if (!sni || !relayedName(sni)) {
      log("refused", { sni: sni || null });
      client.destroy();
      return;
    }
    handle(client, sni, buffered);
  });

  client.on("error", () => client.destroy());
});

async function handle(client, sni, firstBytes) {
  client.pause(); // no data listener between here and pipe(): nothing may be dropped
  const pool = await poolFor(sni);
  const targets = pool.length > 0 ? pool.map((ip) => [ip, 443]) : [[sni, 443]];
  for (const [host, port] of targets) {
    try {
      const { socket, buffered } = await connectViaProxy(host, port);
      socket.write(firstBytes);
      if (buffered.length > 0) client.write(buffered);
      client.pipe(socket);
      socket.pipe(client);
      client.resume();
      socket.resume();
      socket.on("error", () => {
        socket.destroy();
        client.destroy();
      });
      client.on("close", () => socket.destroy());
      socket.on("close", () => client.destroy());
      log("relayed", { sni, target: `${host}:${port}`, viaPool: pool.length > 0 });
      return;
    } catch (error) {
      log("dial_failed", { sni, target: `${host}:${port}`, error: String(error) });
    }
  }
  client.resume();
  client.destroy();
}

server.on("error", (error) => {
  console.error(JSON.stringify({ event: "listen_error", error: String(error) }));
  process.exit(1);
});
server.listen(LISTEN_PORT, LISTEN_IP, () => {
  console.log(JSON.stringify({ event: "listening", ip: LISTEN_IP, port: LISTEN_PORT, domains: DOMAINS.length, proxy: `${PROXY_HOST}:${PROXY_PORT}` }));
});

// ---------------------------------------------------------------- self-check + reporting
// Dial our own listener with a real SNI: the full path (us → proxy → real server, TLS handshake
// included) must work before the DoH server pins anyone to us. Three consecutive failures mark us
// unhealthy; one success recovers.

let consecutiveFailures = 0;

function selfCheck() {
  return new Promise((resolve) => {
    const socket = tls.connect({ host: LISTEN_IP, port: LISTEN_PORT, servername: SELF_CHECK_HOST, rejectUnauthorized: false, timeout: 8000 }, () => {
      socket.destroy();
      resolve(true);
    });
    socket.once("error", () => resolve(false));
    socket.once("timeout", () => {
      socket.destroy();
      resolve(false);
    });
  });
}

async function report() {
  const healthy = consecutiveFailures < 3;
  console.log(JSON.stringify({ event: "self_check", healthy, consecutiveFailures }));
  if (!ADMIN_TOKEN) return;
  try {
    await fetch(`${ADMIN_URL}/admin/relay-health`, {
      method: "POST",
      headers: { Authorization: `Bearer ${ADMIN_TOKEN}`, "Content-Type": "application/json" },
      body: JSON.stringify({ source: `relay@${LISTEN_IP}`, ttl: REPORT_TTL_SECONDS, healthy }),
    });
  } catch (error) {
    log("report_error", { error: String(error) });
  }
}

setInterval(async () => {
  const ok = await selfCheck();
  consecutiveFailures = ok ? 0 : consecutiveFailures + 1;
  await report();
}, CHECK_INTERVAL_SECONDS * 1000).unref();
setTimeout(async () => {
  const ok = await selfCheck();
  consecutiveFailures = ok ? 0 : consecutiveFailures + 1;
  await report();
}, 2000).unref();

process.on("SIGTERM", () => {
  console.log(JSON.stringify({ event: "shutdown" }));
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
});
