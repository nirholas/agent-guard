// Credential vault. Secrets are encrypted at rest with AES-256-GCM under a key
// derived from a passphrase with scrypt. The bot never sees them: the proxy
// injects the upstream credential on the way out.
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

const MAGIC = 'agvault1';

function derive(passphrase, salt) {
	return scryptSync(passphrase, salt, 32, { N: 1 << 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
}

export function openVault(file, passphrase) {
	if (!passphrase) throw new Error('A vault passphrase is required (set AGENT_GUARD_PASSPHRASE).');
	let secrets = {};
	let salt = randomBytes(16);
	if (existsSync(file)) {
		const raw = readFileSync(file);
		if (raw.subarray(0, 8).toString() !== MAGIC) throw new Error('Not an agent-guard vault file.');
		salt = raw.subarray(8, 24);
		const iv = raw.subarray(24, 36);
		const tag = raw.subarray(36, 52);
		const d = createDecipheriv('aes-256-gcm', derive(passphrase, salt), iv);
		d.setAuthTag(tag);
		try {
			secrets = JSON.parse(Buffer.concat([d.update(raw.subarray(52)), d.final()]).toString());
		} catch {
			throw new Error('Wrong passphrase or corrupted vault.');
		}
	}
	const key = derive(passphrase, salt);
	function save() {
		const iv = randomBytes(12);
		const c = createCipheriv('aes-256-gcm', key, iv);
		const enc = Buffer.concat([c.update(JSON.stringify(secrets)), c.final()]);
		mkdirSync(dirname(file), { recursive: true });
		writeFileSync(file, Buffer.concat([Buffer.from(MAGIC), salt, iv, c.getAuthTag(), enc]), { mode: 0o600 });
	}
	return {
		names: () => Object.keys(secrets).sort(),
		get: (name) => secrets[name] ?? null,
		values: () => Object.values(secrets),
		set(name, value) {
			if (!/^[A-Za-z0-9_.-]{1,64}$/.test(name)) throw new Error('Secret names use letters, digits, dot, dash and underscore.');
			secrets[name] = String(value);
			save();
		},
		remove(name) {
			const had = name in secrets;
			delete secrets[name];
			if (had) save();
			return had;
		},
	};
}
