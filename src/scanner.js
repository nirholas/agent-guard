// Heuristic scanners. They catch the common, cheap attacks and the common
// accidents. They are a tripwire, not a proof: see docs/threat-model.md.

const INJECTION_RULES = [
	['override-instructions', /\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|system)\b[^.\n]{0,30}\b(instructions?|prompts?|rules?|directions?)\b/i],
	['new-role', /\byou\s+are\s+now\b[^.\n]{0,60}\b(assistant|agent|developer|admin|root|dan|jailbroken)\b/i],
	['reveal-prompt', /\b(reveal|print|show|output|repeat|leak)\b[^.\n]{0,40}\b(system\s+prompt|hidden\s+instructions?|your\s+instructions?)\b/i],
	['exfiltrate', /\b(send|post|upload|forward|exfiltrate|email)\b[^.\n]{0,60}\b(api[\s_-]?keys?|secrets?|credentials?|passwords?|private\s+keys?|seed\s+phrase|tokens?)\b/i],
	['fake-system-tag', /<\s*\/?\s*(system|assistant|instructions?)\s*>|\[\s*(system|inst)\s*\]|<\|im_(start|end)\|>/i],
	['tool-hijack', /\b(call|invoke|run|execute)\b[^.\n]{0,30}\b(tool|function|command|shell|curl|wget|bash)\b[^.\n]{0,60}\b(without|do not|don't)\b[^.\n]{0,30}\b(ask|confirm|tell|mention|notify)\b/i],
	['hidden-instruction', /\b(do\s+not|don't|never)\s+(tell|inform|mention|alert|show)\s+(the\s+)?(user|human|operator)\b/i],
	['markdown-exfil', /!\[[^\]]*\]\(https?:\/\/[^)\s]*[?&][^)\s]*(secret|token|key|data|prompt)=/i],
];

const ZERO_WIDTH = /[​-‏‪-‮⁠-⁤﻿]{3,}/;

export function scanInjection(text) {
	const hits = [];
	for (const [rule, re] of INJECTION_RULES) if (re.test(text)) hits.push(rule);
	if (ZERO_WIDTH.test(text)) hits.push('hidden-unicode');
	return hits;
}

const SECRET_RULES = [
	['anthropic-key', /sk-ant-[A-Za-z0-9_-]{20,}/],
	['openai-key', /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}/],
	['github-token', /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}/],
	['aws-access-key', /\bAKIA[0-9A-Z]{16}\b/],
	['slack-token', /\bxox[abprs]-[A-Za-z0-9-]{10,}/],
	['private-key-block', /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/],
	['jwt', /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/],
	['solana-secret-array', /\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\]/],
];

export function scanSecrets(text, knownValues = []) {
	const hits = [];
	for (const [rule, re] of SECRET_RULES) if (re.test(text)) hits.push(rule);
	for (const v of knownValues) if (v && v.length >= 8 && text.includes(v)) { hits.push('vault-secret'); break; }
	return hits;
}
