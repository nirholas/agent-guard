// Config loading and validation. Everything is explicit: an upstream that is
// not listed cannot be reached through the guard.
import { readFileSync } from 'node:fs';

export const DEFAULTS = {
	listen: { host: '127.0.0.1', port: 8787 },
	scan: { mode: 'block', max_body_bytes: 5_000_000 },
	egress: { allow_hosts: [], block_secrets: true },
	audit: { file: 'agent-guard-audit.jsonl' },
	vault: { file: 'agent-guard.vault' },
	kill_file: 'AGENT_GUARD_KILL',
};

export function validateConfig(input) {
	const errors = [];
	const c = {
		listen: { ...DEFAULTS.listen, ...input.listen },
		scan: { ...DEFAULTS.scan, ...input.scan },
		egress: { ...DEFAULTS.egress, ...input.egress },
		audit: { ...DEFAULTS.audit, ...input.audit },
		vault: { ...DEFAULTS.vault, ...input.vault },
		kill_file: input.kill_file || DEFAULTS.kill_file,
		clients: input.clients || ['client_token'],
		admin_secret: input.admin_secret || 'admin_token',
		upstreams: input.upstreams || {},
	};
	if (!['block', 'flag'].includes(c.scan.mode)) errors.push('scan.mode must be "block" or "flag".');
	if (!Number.isInteger(c.listen.port) || c.listen.port < 0 || c.listen.port > 65535) errors.push('listen.port must be 0-65535.');
	if (!['127.0.0.1', 'localhost', '::1'].includes(c.listen.host) && !input.listen?.allow_remote) {
		errors.push('listen.host must be loopback unless listen.allow_remote is true.');
	}
	for (const [name, u] of Object.entries(c.upstreams)) {
		if (!/^[a-z0-9-]{1,32}$/.test(name)) errors.push(`upstream "${name}": names are lowercase letters, digits and dashes.`);
		try {
			const t = new URL(u.target);
			if (t.protocol !== 'https:' && !['127.0.0.1', 'localhost'].includes(t.hostname)) errors.push(`upstream "${name}": target must be https.`);
		} catch {
			errors.push(`upstream "${name}": target is not a valid URL.`);
		}
		if (u.inject && !(u.inject.header && u.inject.secret)) errors.push(`upstream "${name}": inject needs header and secret.`);
		if (u.rate_per_min != null && !(u.rate_per_min > 0)) errors.push(`upstream "${name}": rate_per_min must be positive.`);
	}
	if (errors.length) {
		const e = new Error(`Invalid config:\n- ${errors.join('\n- ')}`);
		e.errors = errors;
		throw e;
	}
	return c;
}

export function loadConfig(file) {
	return validateConfig(JSON.parse(readFileSync(file, 'utf8')));
}
