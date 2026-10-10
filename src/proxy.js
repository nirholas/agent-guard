// The guard. Two surfaces on one loopback port:
//   /u/<upstream>/...   reverse proxy to a configured API, credential injected
//   CONNECT host:port   tunnel to an allow-listed host, audited, not inspected
//   /_guard/...         admin: status, kill, resume (bearer admin token)
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { existsSync, writeFileSync, rmSync } from 'node:fs';
import { createHash, timingSafeEqual } from 'node:crypto';
import { scanInjection, scanSecrets } from './scanner.js';

const digest = (s) => createHash('sha256').update(s).digest();
const safeEqual = (a, b) => timingSafeEqual(digest(a), digest(b));
const HOP = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'host', 'content-length']);

function readBody(req, limit) {
	return new Promise((resolve, reject) => {
		const chunks = [];
		let size = 0;
		req.on('data', (c) => {
			size += c.length;
			if (size > limit) { reject(Object.assign(new Error('body too large'), { status: 413 })); req.destroy(); return; }
			chunks.push(c);
		});
		req.on('end', () => resolve(Buffer.concat(chunks)));
		req.on('error', reject);
	});
}

export function createGuard({ config, vault, audit, fetchAgent = {} }) {
	const buckets = new Map();
	const stats = { requests: 0, blocked: 0, flagged: 0, tunnels: 0, started: Date.now() };

	const killed = () => existsSync(config.kill_file);
	const clientOk = (req) => {
		const presented = (req.headers['x-guard-token'] || req.headers['x-api-key'] || (req.headers.authorization || '').replace(/^Bearer\s+/i, '')).toString();
		if (!presented) return false;
		return config.clients.some((name) => { const t = vault.get(name); return t && safeEqual(presented, t); });
	};
	const adminOk = (req) => {
		const t = vault.get(config.admin_secret);
		const p = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
		return Boolean(t && p && safeEqual(p, t));
	};
	const limited = (name, perMin) => {
		const now = Date.now();
		const b = (buckets.get(name) || []).filter((t) => now - t < 60_000);
		if (b.length >= perMin) { buckets.set(name, b); return true; }
		b.push(now);
		buckets.set(name, b);
		return false;
	};
	const deny = (res, status, code, extra = {}) => {
		stats.blocked++;
		res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
		res.end(JSON.stringify({ error: code, ...extra }));
	};

	async function handleAdmin(req, res, path) {
		if (!adminOk(req)) return deny(res, 401, 'unauthorized');
		if (path === '/_guard/status' && req.method === 'GET') {
			res.writeHead(200, { 'content-type': 'application/json' });
			return res.end(JSON.stringify({ killed: killed(), upstreams: Object.keys(config.upstreams), scan_mode: config.scan.mode, ...stats, uptime_s: Math.round((Date.now() - stats.started) / 1000) }));
		}
		if (path === '/_guard/kill' && req.method === 'POST') {
			writeFileSync(config.kill_file, new Date().toISOString());
			audit.write('kill', { via: 'admin' });
			res.writeHead(200, { 'content-type': 'application/json' });
			return res.end(JSON.stringify({ killed: true }));
		}
		if (path === '/_guard/resume' && req.method === 'POST') {
			rmSync(config.kill_file, { force: true });
			audit.write('resume', { via: 'admin' });
			res.writeHead(200, { 'content-type': 'application/json' });
			return res.end(JSON.stringify({ killed: false }));
		}
		return deny(res, 404, 'not_found');
	}

	async function handleUpstream(req, res, url) {
		stats.requests++;
		const [, , name, ...rest] = url.pathname.split('/');
		const up = config.upstreams[name];
		const id = `${name}:${req.method}:${url.pathname}`;
		if (killed()) { audit.write('deny', { id, reason: 'killed' }); return deny(res, 503, 'killed'); }
		if (!clientOk(req)) { audit.write('deny', { id, reason: 'bad_client_token' }); return deny(res, 401, 'unauthorized'); }
		if (!up) { audit.write('deny', { id, reason: 'unknown_upstream' }); return deny(res, 404, 'unknown_upstream'); }
		if (up.rate_per_min && limited(name, up.rate_per_min)) { audit.write('deny', { id, reason: 'rate_limited' }); return deny(res, 429, 'rate_limited'); }

		let body = Buffer.alloc(0);
		try { body = await readBody(req, config.scan.max_body_bytes); } catch (e) {
			audit.write('deny', { id, reason: 'body_too_large' });
			return deny(res, e.status || 400, 'body_too_large');
		}
		if (config.egress.block_secrets && body.length) {
			const hits = scanSecrets(body.toString('utf8'), vault.values());
			if (hits.length) { audit.write('deny', { id, reason: 'secret_in_request', rules: hits }); return deny(res, 403, 'secret_in_request', { rules: hits }); }
		}

		const target = new URL(up.target);
		const headers = {};
		for (const [k, v] of Object.entries(req.headers)) {
			if (HOP.has(k) || k === 'x-guard-token' || k === 'authorization' || k === 'cookie') continue;
			if (k === 'x-api-key' && clientOk({ headers: { 'x-guard-token': v } })) continue;
			headers[k] = v;
		}
		if (up.inject) {
			const secret = vault.get(up.inject.secret);
			if (!secret) { audit.write('deny', { id, reason: 'missing_upstream_secret' }); return deny(res, 502, 'missing_upstream_secret'); }
			headers[up.inject.header.toLowerCase()] = (up.inject.prefix || '') + secret;
		}
		headers.host = target.host;
		if (body.length) headers['content-length'] = String(body.length);

		const lib = target.protocol === 'https:' ? https : http;
		const path = '/' + rest.join('/') + url.search;
		const started = Date.now();
		audit.write('request', { id, bytes: body.length });

		const out = lib.request({ protocol: target.protocol, hostname: target.hostname, port: target.port || undefined, method: req.method, path: (target.pathname.replace(/\/$/, '') + path), headers, ...fetchAgent }, (ures) => {
			const ctype = String(ures.headers['content-type'] || '');
			const textual = /json|text|xml|html|event-stream|javascript/.test(ctype);
			const outHeaders = {};
			for (const [k, v] of Object.entries(ures.headers)) if (!HOP.has(k)) outHeaders[k] = v;
			const stream = ctype.includes('event-stream');

			if (!textual) {
				res.writeHead(ures.statusCode, outHeaders);
				ures.pipe(res);
				ures.on('end', () => audit.write('response', { id, status: ures.statusCode, ms: Date.now() - started, scanned: false }));
				return;
			}
			if (!stream) {
				const chunks = [];
				let size = 0;
				ures.on('data', (c) => { size += c.length; if (size <= config.scan.max_body_bytes) chunks.push(c); });
				ures.on('end', () => {
					const buf = Buffer.concat(chunks);
					const hits = size <= config.scan.max_body_bytes ? scanInjection(buf.toString('utf8')) : [];
					audit.write('response', { id, status: ures.statusCode, ms: Date.now() - started, scanned: size <= config.scan.max_body_bytes, injection: hits });
					if (hits.length && config.scan.mode === 'block') return deny(res, 502, 'injection_suspected', { rules: hits });
					if (hits.length) stats.flagged++;
					res.writeHead(ures.statusCode, { ...outHeaders, 'content-length': String(buf.length), ...(hits.length ? { 'x-guard-flags': hits.join(',') } : {}) });
					res.end(buf);
				});
				return;
			}
			res.writeHead(ures.statusCode, outHeaders);
			let tail = '';
			let tripped = false;
			ures.on('data', (c) => {
				if (tripped) return;
				const window = tail + c.toString('utf8');
				tail = window.slice(-300);
				const hits = scanInjection(window);
				if (hits.length) {
					audit.write('stream_injection', { id, rules: hits, action: config.scan.mode });
					if (config.scan.mode === 'block') { tripped = true; stats.blocked++; ures.destroy(); res.end(); return; }
					stats.flagged++;
				}
				res.write(c);
			});
			ures.on('end', () => { if (!tripped) res.end(); audit.write('response', { id, status: ures.statusCode, ms: Date.now() - started, scanned: true, stream: true }); });
		});
		out.on('error', (e) => { audit.write('upstream_error', { id, message: e.code || e.message }); if (!res.headersSent) deny(res, 502, 'upstream_unreachable'); else res.end(); });
		out.end(body);
	}

	const server = http.createServer(async (req, res) => {
		const url = new URL(req.url, 'http://guard.local');
		try {
			if (url.pathname.startsWith('/_guard/')) return await handleAdmin(req, res, url.pathname);
			if (url.pathname.startsWith('/u/')) return await handleUpstream(req, res, url);
			return deny(res, 404, 'not_found');
		} catch (e) {
			audit.write('error', { message: e.message });
			if (!res.headersSent) deny(res, 500, 'internal');
		}
	});

	server.on('connect', (req, socket, head) => {
		const [host, port = '443'] = req.url.split(':');
		const allowed = config.egress.allow_hosts.some((h) => host === h || (h.startsWith('*.') && host.endsWith(h.slice(1))));
		const auth = clientOk({ headers: { 'x-guard-token': proxyToken(req) } });
		if (killed() || !auth || !allowed) {
			audit.write('deny', { id: `CONNECT ${req.url}`, reason: killed() ? 'killed' : !auth ? 'bad_client_token' : 'host_not_allowed' });
			stats.blocked++;
			socket.end('HTTP/1.1 403 Forbidden\r\n\r\n');
			return;
		}
		stats.tunnels++;
		audit.write('tunnel', { id: `CONNECT ${host}:${port}` });
		const upstream = net.connect(Number(port), host, () => {
			socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
			upstream.write(head);
			upstream.pipe(socket);
			socket.pipe(upstream);
		});
		upstream.on('error', () => socket.destroy());
		socket.on('error', () => upstream.destroy());
	});

	function proxyToken(req) {
		const h = req.headers['proxy-authorization'] || '';
		const m = /^Basic\s+(.+)$/i.exec(h);
		if (m) return Buffer.from(m[1], 'base64').toString().split(':').slice(1).join(':');
		return h.replace(/^Bearer\s+/i, '');
	}

	return {
		server,
		stats,
		listen: () => new Promise((resolve) => server.listen(config.listen.port, config.listen.host, () => resolve(server.address()))),
		close: () => new Promise((resolve) => { server.closeAllConnections?.(); server.close(resolve); }),
	};
}
