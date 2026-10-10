#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { loadConfig, DEFAULTS } from '../src/config.js';
import { openVault } from '../src/vault.js';
import { createAudit, verifyAudit } from '../src/audit.js';
import { createGuard } from '../src/proxy.js';

const [cmd, ...args] = process.argv.slice(2);
const flag = (name, d) => { const i = args.indexOf(`--${name}`); return i >= 0 ? args[i + 1] : d; };
const configFile = flag('config', 'agent-guard.json');
const pass = () => process.env.AGENT_GUARD_PASSPHRASE;
const die = (m, code = 1) => { console.error(m); process.exit(code); };

const HELP = `agent-guard: a local guard and egress proxy for always-on AI agents

  agent-guard init                       write agent-guard.json and create the vault with fresh tokens
  agent-guard start [--config file]      run the guard
  agent-guard vault set <name> [value]   store a secret (value read from stdin when omitted)
  agent-guard vault list                 list secret names (never values)
  agent-guard vault remove <name>
  agent-guard kill | resume              toggle the kill switch (file based, works with the guard stopped)
  agent-guard audit verify [--file f]    check the audit log hash chain
  agent-guard audit tail [--file f]      print recent audit entries

Set AGENT_GUARD_PASSPHRASE to unlock the vault.`;

async function stdin() { let s = ''; for await (const c of process.stdin) s += c; return s.trim(); }

async function main() {
	switch (cmd) {
		case 'init': {
			if (existsSync(configFile)) die(`${configFile} already exists.`);
			if (!pass()) die('Set AGENT_GUARD_PASSPHRASE first. It encrypts the vault.');
			const cfg = { ...DEFAULTS, upstreams: { example: { target: 'https://api.example.com', inject: { header: 'authorization', prefix: 'Bearer ', secret: 'example_key' }, rate_per_min: 120 } } };
			writeFileSync(configFile, JSON.stringify(cfg, null, 2) + '\n');
			const v = openVault(cfg.vault.file, pass());
			const client = randomBytes(24).toString('hex');
			v.set('client_token', client);
			v.set('admin_token', randomBytes(24).toString('hex'));
			console.log(`Wrote ${configFile} and ${cfg.vault.file}.\nClient token (give this to your bot, once): ${client}\nEdit upstreams, then: agent-guard vault set example_key`);
			return;
		}
		case 'start': {
			const config = loadConfig(configFile);
			const vault = openVault(config.vault.file, pass());
			const audit = createAudit(config.audit.file);
			const guard = createGuard({ config, vault, audit });
			const addr = await guard.listen();
			audit.write('start', { port: addr.port });
			console.log(`agent-guard listening on http://${config.listen.host}:${addr.port}  (scan: ${config.scan.mode}, upstreams: ${Object.keys(config.upstreams).join(', ') || 'none'})`);
			const stop = async () => { audit.write('stop'); await guard.close(); process.exit(0); };
			process.on('SIGINT', stop);
			process.on('SIGTERM', stop);
			return;
		}
		case 'vault': {
			const [sub, name, value] = args;
			const config = loadConfig(configFile);
			const v = openVault(config.vault.file, pass());
			if (sub === 'set') { v.set(name, value ?? (await stdin())); console.log(`stored ${name}`); }
			else if (sub === 'list') console.log(v.names().join('\n') || '(empty)');
			else if (sub === 'remove') console.log(v.remove(name) ? `removed ${name}` : 'no such secret');
			else die(HELP);
			return;
		}
		case 'kill': {
			const f = (existsSync(configFile) ? loadConfig(configFile).kill_file : DEFAULTS.kill_file);
			writeFileSync(f, new Date().toISOString());
			console.log(`Kill switch on (${f}). Every request is refused until: agent-guard resume`);
			return;
		}
		case 'resume': {
			const f = (existsSync(configFile) ? loadConfig(configFile).kill_file : DEFAULTS.kill_file);
			rmSync(f, { force: true });
			console.log('Kill switch off.');
			return;
		}
		case 'audit': {
			const file = flag('file', existsSync(configFile) ? loadConfig(configFile).audit.file : DEFAULTS.audit.file);
			if (args[0] === 'verify') {
				const r = verifyAudit(file);
				console.log(r.ok ? `OK: ${r.entries} entries, chain intact` : `BROKEN at line ${r.line}: ${r.reason}`);
				process.exit(r.ok ? 0 : 2);
			}
			if (args[0] === 'tail') { console.log(readFileSync(file, 'utf8').trimEnd().split('\n').slice(-20).join('\n')); return; }
			die(HELP);
			return;
		}
		default:
			console.log(HELP);
	}
}
main().catch((e) => die(e.message));
