/**
 * Redaction of secret-looking material.
 *
 * `action.resource` is the one human-readable field in an event, and it holds
 * the command or path that ran — which is exactly where a token ends up when
 * someone writes `curl -H "Authorization: Bearer …"`. Lineage is long-lived and
 * meant to be exported as evidence, so anything recorded or displayed passes
 * through here first.
 *
 * Two rules shape the pattern list:
 *
 *   1. Redact on **structure**, not entropy: a named credential flag, a URL
 *      userinfo field, a known token prefix. Entropy heuristics would eat commit
 *      SHAs, digests and base64 file contents, which are the things an auditor
 *      most needs to read.
 *   2. Keep the shape of the command intact, so `curl -H 'Authorization:
 *      [redacted:bearer]' https://api.example.com` still says what happened.
 *
 * This is defence in depth, not a guarantee. The reliable protection is not
 * putting secrets on a command line at all, which is what the credential broker
 * in a later release is for.
 */

const MARK = (kind) => `[redacted:${kind}]`;

/**
 * Ordered: earlier rules win, so a specific vendor prefix is labelled as such
 * before a generic flag rule can claim it.
 *
 * @type {{name: string, re: RegExp, replace: (m: string, ...g: string[]) => string}[]}
 */
const RULES = [
  // Authorization / Proxy-Authorization header values, any scheme.
  {
    name: 'bearer',
    re: /\b(Authorization|Proxy-Authorization)\s*:\s*(Bearer|Basic|Token|ApiKey|Digest)\s+[^\s'"`;|&]+/gi,
    replace: (_m, header, scheme) => `${header}: ${scheme} ${MARK('bearer')}`,
  },

  // Credentials in a URL: scheme://user:password@host
  {
    name: 'url-userinfo',
    re: /([a-z][a-z0-9+.-]*:\/\/)([^\s/:@'"]+):([^\s/@'"]+)@/gi,
    replace: (_m, scheme, user) => `${scheme}${user}:${MARK('url-password')}@`,
  },

  // Sensitive query parameters.
  {
    name: 'query-param',
    re: /([?&](?:access_token|refresh_token|id_token|api_key|apikey|auth|token|key|secret|password|passwd|pwd|signature|sig|sas|code)=)([^&\s'"`]+)/gi,
    replace: (_m, prefix) => `${prefix}${MARK('query-param')}`,
  },

  // Known vendor token shapes. Prefix plus body, so the kind stays visible.
  {
    name: 'vendor-token',
    re: /\b(sk-ant-[A-Za-z0-9_-]{6,}|sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|ghu_[A-Za-z0-9]{20,}|ghs_[A-Za-z0-9]{20,}|ghr_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}|npm_[A-Za-z0-9]{30,}|hf_[A-Za-z0-9]{20,}|dop_v1_[a-f0-9]{32,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,})\b/g,
    replace: () => MARK('token'),
  },

  // JSON Web Tokens.
  {
    name: 'jwt',
    re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    replace: () => MARK('jwt'),
  },

  // --password=… / --token secret / -p secret, long and short forms.
  {
    name: 'credential-flag',
    re: /(--?(?:password|passwd|pwd|token|api[-_]?key|apikey|secret|secret[-_]?key|access[-_]?key|access[-_]?token|auth[-_]?token|client[-_]?secret|private[-_]?key|credential|bearer)(?:\s+|=))(?!\[redacted)("[^"]*"|'[^']*'|[^\s'"`;|&]+)/gi,
    replace: (_m, flag) => `${flag}${MARK('credential')}`,
  },

  // Environment-style assignments: FOO_TOKEN=…, DB_PASSWORD=…
  {
    name: 'env-assignment',
    re: /\b([A-Z][A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIALS?)[A-Z0-9_]*)=(?!\[redacted)("[^"]*"|'[^']*'|[^\s'"`;|&]+)/g,
    replace: (_m, name) => `${name}=${MARK('credential')}`,
  },

  // Positional secret after an AWS-style setter.
  {
    name: 'aws-configure',
    re: /\b(aws_secret_access_key|aws_session_token|aws_access_key_id)(\s+)(?!\[redacted)([^\s'"`;|&]+)/gi,
    replace: (_m, key, gap) => `${key}${gap}${MARK('credential')}`,
  },

  // PEM material pasted into a command line.
  {
    name: 'pem',
    re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g,
    replace: () => MARK('private-key'),
  },
];

/**
 * Redact secret-looking material from a string.
 *
 * @param {unknown} text
 * @returns {string}
 */
export function redact(text) {
  if (text === null || text === undefined) return '';
  let out = String(text);
  for (const rule of RULES) out = out.replace(rule.re, rule.replace);
  return out;
}

/**
 * True when redaction changed the text. Used to flag an event so a reader knows
 * the resource is not verbatim.
 *
 * @param {unknown} text
 * @returns {{value: string, redacted: boolean}}
 */
export function redactWithFlag(text) {
  const original = text === null || text === undefined ? '' : String(text);
  const value = redact(original);
  return { value, redacted: value !== original };
}

/** Rule names, for tests and documentation. */
export const REDACTION_RULES = RULES.map((r) => r.name);
