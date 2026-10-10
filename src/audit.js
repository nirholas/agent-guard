// Append-only, hash-chained audit log. Each line carries the sha256 of the
// previous line, so editing or deleting any earlier entry breaks verification.
import { appendFileSync, existsSync, readFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname } from 'node:path';

const GENESIS = '0'.repeat(64);
const sha = (s) => createHash('sha256').update(s).digest('hex');

function lastHash(file) {
	if (!existsSync(file)) return GENESIS;
	const lines = readFileSync(file, 'utf8').trimEnd().split('\n').filter(Boolean);
	if (!lines.length) return GENESIS;
	return JSON.parse(lines[lines.length - 1]).hash;
}

export function createAudit(file, { now = () => new Date() } = {}) {
	mkdirSync(dirname(file), { recursive: true });
	let prev = lastHash(file);
	return {
		file,
		write(event, data = {}) {
			const body = JSON.stringify({ ts: now().toISOString(), event, ...data, prev });
			const hash = sha(body);
			appendFileSync(file, JSON.stringify({ ...JSON.parse(body), hash }) + '\n', { mode: 0o600 });
			prev = hash;
			return hash;
		},
	};
}

export function verifyAudit(file) {
	if (!existsSync(file)) return { ok: true, entries: 0 };
	const lines = readFileSync(file, 'utf8').split('\n').filter(Boolean);
	let prev = GENESIS;
	for (let i = 0; i < lines.length; i++) {
		let rec;
		try { rec = JSON.parse(lines[i]); } catch { return { ok: false, entries: i, line: i + 1, reason: 'unparseable line' }; }
		const { hash, ...rest } = rec;
		if (rest.prev !== prev) return { ok: false, entries: i, line: i + 1, reason: 'chain broken' };
		if (sha(JSON.stringify(rest)) !== hash) return { ok: false, entries: i, line: i + 1, reason: 'entry modified' };
		prev = hash;
	}
	return { ok: true, entries: lines.length };
}
