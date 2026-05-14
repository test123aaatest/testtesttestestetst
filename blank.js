export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const secureToken = env.TOKEN;
    const adminPath = (env.ADMIN || "").toLowerCase();
    if (!secureToken || !adminPath) return new Response('Unauthorized Config', { status: 500 });
    if (url.pathname.toLowerCase() === `/${adminPath}`) {
      const reqToken = request.headers.get('Authorization')?.replace('Bearer ', '') || url.searchParams.get("token");
      if (!reqToken || !await safeTimeCompare(reqToken, secureToken)) return new Response('Not Found', { status: 404 });
      return await handleSecureSubscriptionResponse(request, url, env);
    }
    if (request.headers.get('Upgrade') === 'websocket') {
      if (env.STRICT_ORIGIN === "true") {
        const origin = request.headers.get('Origin');
        if (origin) { try { if (new URL(origin).host !== url.host) return new Response('Forbidden', { status: 403 }); } catch { return new Response('Forbidden', { status: 403 }); } }
      }
      return await handleWebSocketTunnel(request, env, ctx);
    }
    return new Response('', { status: 200 });
  }
};

async function safeTimeCompare(a, b) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", new Uint8Array(32), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sA = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(a)));
  const sB = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(b)));
  let d = 0; for (let i = 0; i < sA.length; i++) d |= sA[i] ^ sB[i]; return d === 0;
}

function getCryptoRandomElement(arr) {
  if (!arr?.length) return null;
  const v = new Uint32Array(1); crypto.getRandomValues(v); return arr[v[0] % arr.length];
}

function isSafeIP(ipStr) {
  let ip = ipStr.replace(/[\[\]]/g, '').trim().toLowerCase();
  if (ip.includes("::ffff:")) {
    const parts = ip.split(":"); const last = parts[parts.length - 1];
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(last)) ip = last;
  }
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
    const o = ip.split('.').map(Number);
    if (o.some(v => v < 0 || v > 255)) return false;
    if (o[0] === 0 || o[0] === 10 || o[0] === 127) return false;
    if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return false;
    if (o[0] === 169 && o[1] === 254) return false;
    if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return false;
    if (o[0] === 192 && o[1] === 168) return false;
    if (o[0] === 198 && (o[1] === 18 || o[1] === 19)) return false;
    return true;
  }
  if (/^[0-9a-f:]+$/.test(ip)) {
    if (ip === "::1" || ip === "::" || ip === "0:0:0:0:0:0:0:1") return false;
    if (/^(fe80|fc|fd|ff)/.test(ip)) return false;
    const m = ip.match(/::?ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})/i);
    if (m) {
      const p1 = parseInt(m[1], 16), p2 = parseInt(m[2], 16);
      if (isNaN(p1) || isNaN(p2)) return false;
      return isSafeIP(`${p1 >>> 8}.${p1 & 0xff}.${p2 >>> 8}.${p2 & 0xff}`);
    }
    return true;
  }
  return false;
}

function isSafeHost(host) {
  const c = host.replace(/[\[\]]/g, '').trim();
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(c) || /^[0-9a-f:]+$/i.test(c)) return isSafeIP(c);
  const lower = c.toLowerCase();
  if (['localhost', 'ip6-localhost', 'ip6-loopback', 'metadata.google.internal', 'instance-data'].includes(lower)) return false;
  if (lower.endsWith('.internal') || lower.endsWith('.local') || lower.endsWith('.localhost')) return false;
  return true;
}

async function handleSecureSubscriptionResponse(request, url, env) {
  const ua = (request.headers.get('User-Agent') || '').toLowerCase();
  let type = 'html';
  if (ua.includes('clash') || url.searchParams.get('clash') === '1') type = 'clash';
  else if (!/mozilla|chrome|safari/i.test(ua)) type = 'base64';

  const secH = {
    'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'self'; script-src 'unsafe-inline';",
    'Cache-Control': 'private, no-store, must-revalidate'
  };

  if (!env.UUID_STORE) return new Response('Missing KV Binding', { status: 500 });

  const now = Date.now();
  const lastRotate = parseInt(await env.UUID_STORE.get("LAST_ROTATE_TIME") || "0");
  let uuid = await env.UUID_STORE.get("CURRENT_SECURE_UUID");
  if (!uuid || (now - lastRotate > 300000)) {
    const newUuid = crypto.randomUUID();
    if (uuid) await env.UUID_STORE.put("OLD_SECURE_UUID", uuid, { expirationTtl: 600 });
    await env.UUID_STORE.put("CURRENT_SECURE_UUID", newUuid);
    await env.UUID_STORE.put("LAST_ROTATE_TIME", now.toString());
    uuid = newUuid;
  }

  const ips = (env.CLEAN_IPS || "cloudflare.com,104.16.123.96,172.67.73.4")
    .split(',').map(s => s.trim()).filter(s => s && isSafeHost(s));
  if (!ips.length) ips.push("cloudflare.com");

  if (type === 'html') {
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Console</title><meta name="viewport" content="width=device-width,initial-scale=1"><style>body{font-family:-apple-system,sans-serif;background:#fafafa;padding:20px}.box{max-width:650px;margin:0 auto;background:#fff;padding:20px;border-radius:6px;box-shadow:0 2px 6px rgba(0,0,0,.05)}pre{background:#1e1e2e;color:#cdd6f4;padding:12px;border-radius:4px;white-space:pre-wrap;word-break:break-all;font-size:12px}</style></head><body><div class="box"><h2>🛠️ Console</h2><hr><h3>📥 Subscriptions</h3><p>Universal:</p><pre id="sub"></pre><p>Clash:</p><pre id="clash"></pre></div><script>const u=location.origin+location.pathname+location.search;document.getElementById("sub").innerText=u;document.getElementById("clash").innerText=u+"&clash=1";</script></body></html>`;
    return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8', ...secH } });
  }

  const host = url.host;
  const vless = ips.map((ip, i) => `vless://${uuid}@${ip}:443?encryption=none&security=tls&sni=${host}&fp=randomized&type=ws&host=${host}&path=%2F#Node-${i + 1}`).join('\n');
  const proxies = ips.map((ip, i) => `  - name: "Node-${i + 1}"\n    type: vless\n    server: ${ip}\n    port: 443\n    uuid: ${uuid}\n    cipher: auto\n    tls: true\n    udp: true\n    servername: ${host}\n    network: ws\n    ws-opts:\n      path: /\n      headers:\n        Host: ${host}`).join('\n');
  const names = ips.map((_, i) => `      - "Node-${i + 1}"`).join('\n');
  const nodeNames = ips.map((_, i) => `Node-${i + 1}`).join(', ');
  const yaml = `mixed-port: 7890\nallow-lan: false\nmode: rule\nlog-level: error\nipv6: true\ndns:\n  enable: true\n  listen: 0.0.0.0:53\n  enhanced-mode: fake-ip\n  nameserver:\n    - 1.1.1.1\n    - 223.5.5.5\n  fallback:\n    - 8.8.8.8\nproxies:\n${proxies}\nproxy-groups:\n  - name: 🚀 代理中心\n    type: select\n    proxies: [⚡ 自动选择, 🔮 负载均衡, ${nodeNames}, DIRECT]\n  - name: ⚡ 自动选择\n    type: url-test\n    url: cloudflare.com\n    interval: 1800\n    tolerance: 50\n    proxies:\n${names}\n  - name: 🔮 负载均衡\n    type: load-balance\n    url: cloudflare.com\n    interval: 1800\n    strategy: round-robin\n    proxies:\n${names}\nrules:\n  - GEOIP,CN,DIRECT\n  - MATCH,🚀 代理中心`;

  if (type === 'clash') return new Response(yaml, { headers: { 'Content-Type': 'text/yaml; charset=utf-8', ...secH } });
  return new Response(btoa(vless), { headers: { 'Content-Type': 'text/plain; charset=utf-8', ...secH } });
}

async function handleWebSocketTunnel(request, env, ctx) {
  if (!env.UUID_STORE) return new Response('Incomplete Config', { status: 500 });
  const uuid = await env.UUID_STORE.get("CURRENT_SECURE_UUID");
  const oldUuid = await env.UUID_STORE.get("OLD_SECURE_UUID");
  if (!uuid) return new Response('Database Init Required', { status: 500 });
  const proxyIPs = (env.PROXYIP || "").split(',').map(s => s.trim()).filter(s => s && isSafeHost(s));

  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);
  server.accept();
  let remote = null, writer = null, reader = null;
  const state = { closed: false };
  let queue = Promise.resolve();
  let hsStarted = false;
  const hsDeadline = Date.now() + 5000;

  const close = () => { state.closed = true; server.close(); cleanup(remote, reader, writer); };

  server.addEventListener('message', async (event) => {
    try {
      const data = event.data;
      if (state.closed || data.byteLength > 1048576) { close(); return; }

      if (!remote) {
        if (hsStarted) return;
        hsStarted = true;
        if (Date.now() > hsDeadline) { close(); return; }
        if (!data || data.byteLength < 22) { close(); return; }

        const v = new DataView(data);
        if (v.getUint8(0) !== 0) { close(); return; }

        const raw = [...new Uint8Array(data.slice(1, 17))].map(b => b.toString(16).padStart(2, '0')).join('');
        const fmt = `${raw.slice(0,8)}-${raw.slice(8,12)}-${raw.slice(12,16)}-${raw.slice(16,20)}-${raw.slice(20)}`;
        const ok = await safeTimeCompare(fmt, uuid) || (oldUuid && await safeTimeCompare(fmt, oldUuid));
        if (!ok) { close(); return; }

        const pOff = 18 + v.getUint8(17);
        if (data.byteLength < pOff + 3) { close(); return; }
        const port = v.getUint16(pOff);
        const atype = v.getUint8(pOff + 2);
        let host = '', aOff = pOff + 3;

        if (atype === 1) {
          if (data.byteLength < aOff + 4) { close(); return; }
          host = [...new Uint8Array(data.slice(aOff, aOff + 4))].join('.'); aOff += 4;
        } else if (atype === 2) {
          if (data.byteLength < aOff + 16) { close(); return; }
          const b = new Uint8Array(data.slice(aOff, aOff + 16)); const c = [];
          for (let i = 0; i < 16; i += 2) c.push(((b[i] << 8) | b[i + 1]).toString(16));
          host = `[${c.join(':')}]`; aOff += 16;
        } else if (atype === 3) {
          const len = v.getUint8(aOff);
          if (data.byteLength < aOff + 1 + len) { close(); return; }
          host = new TextDecoder().decode(data.slice(aOff + 1, aOff + 1 + len)); aOff += 1 + len;
        } else { close(); return; }

        if (!isSafeHost(host)) { close(); return; }
        const target = (proxyIPs.length ? getCryptoRandomElement(proxyIPs) : host).replace(/[\[\]]/g, '').trim();
        // @ts-ignore
        remote = connect({ hostname: target, port });
        writer = remote.writable.getWriter();
        reader = remote.readable.getReader();

        (async () => {
          try {
            while (!state.closed) {
              let timer;
              const idle = new Promise((_, r) => { timer = setTimeout(() => r(new Error('Idle')), 120000); });
              try {
                const res = await Promise.race([reader.read(), idle]);
                clearTimeout(timer);
                if (res.done || state.closed) break;
                server.send(res.value);
              } catch (e) {
                clearTimeout(timer);
                if (e.message === 'Idle') { state.closed = true; break; }
                throw e;
              }
            }
          } catch {} finally { close(); }
        })();

        if (data.byteLength > aOff) {
          queue = queue.then(async () => { if (!state.closed && writer) try { await writer.write(data.slice(aOff)); } catch { close(); } });
        }
      } else {
        queue = queue.then(async () => { if (!state.closed && writer) try { await writer.write(data); } catch { close(); } });
      }
    } catch { close(); }
  });

  server.addEventListener('close', () => { state.closed = true; cleanup(remote, reader, writer); });
  return new Response(null, { status: 101, webSocket: client });
}

function cleanup(socket, reader, writer) {
  if (writer) { try { writer.close(); } catch { try { writer.releaseLock(); } catch {} } }
  if (reader) { try { reader.cancel(); } catch {} try { reader.releaseLock(); } catch {} }
  if (socket) { try { socket.close(); } catch {} }
}