import { test } from 'node:test';
import assert from 'node:assert/strict';

import { redact, redactWithFlag } from '../src/core/redact.js';

/**
 * Sample secrets are assembled at runtime and never written as contiguous
 * literals. A realistic token in a source file trips GitHub push protection —
 * it blocked this very file once — and every other scanner a contributor runs,
 * which would make the suite unpushable. Splitting the prefix leaves the
 * pattern under test byte-identical at runtime.
 */
const t = (...parts) => parts.join('');

const ANTHROPIC = t('sk-', 'ant-', 'api03-Zx9ZQfakeTOKENvalue123456');
const GH_PAT = t('ghp', '_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH12');
const GH_PAT2 = t('ghp', '_ZZZZYYYYXXXXWWWWVVVVUUUUTTTTSSSS99');
const AWS_SECRET = t('wJalrXUtnFEMI', 'fakeK7MDENGbPxRfiCYEXAMPLEKEY');
const AWS_KEY_ID = t('AKIA', 'IOSFODNN7EXAMPLE');
const SLACK = t('xoxb', '-1234567890-abcdefghijkl');
const GOOGLE = t('AIza', 'SyD-fake_key_value_1234567890abcdef');
const GITLAB = t('glpat', '-FAKEfakeFAKEfake1234');
const JWT = t(
  'eyJ',
  'hbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk',
);

/**
 * Each case is a real shape of secret that ends up on a command line. Two
 * assertions apply to every one: the secret is gone, and enough of the command
 * survives that an auditor can still read what happened.
 */
const SECRETS = [
  {
    name: 'bearer token in a header',
    input: `curl -H 'Authorization: Bearer ${ANTHROPIC}' https://api.example.com/v1`,
    secret: ANTHROPIC,
    keep: ['curl', 'Authorization', 'https://api.example.com/v1'],
  },
  {
    name: 'basic auth header',
    input: 'curl -H "Authorization: Basic dXNlcjpwYXNzd29yZA==" https://api.example.com',
    secret: 'dXNlcjpwYXNzd29yZA==',
    keep: ['Authorization', 'Basic'],
  },
  {
    name: 'credentials in a clone URL',
    input: `git clone https://someone:${GH_PAT}@github.com/acme/api`,
    secret: GH_PAT,
    keep: ['git clone', 'someone', 'github.com/acme/api'],
  },
  {
    name: 'access token in a query string',
    input: 'curl "https://api.example.com/data?user=me&access_token=abc123def456ghi789&page=2"',
    secret: 'abc123def456ghi789',
    keep: ['api.example.com/data', 'user=me', 'page=2'],
  },
  {
    name: 'long-form password flag',
    input: 'psql --password=SuperSecret123! -h db.internal -U admin',
    secret: 'SuperSecret123!',
    keep: ['psql', 'db.internal', 'admin'],
  },
  {
    name: 'space-separated token flag',
    input: `gh auth login --with-token ${GH_PAT2}`,
    secret: GH_PAT2,
    keep: ['gh auth login'],
  },
  {
    name: 'environment-style assignment',
    input: 'DATABASE_PASSWORD=hunter2hunter2 npm run migrate',
    secret: 'hunter2hunter2',
    keep: ['DATABASE_PASSWORD', 'npm run migrate'],
  },
  {
    name: 'aws configure positional secret',
    input: `aws configure set aws_secret_access_key ${AWS_SECRET}`,
    secret: AWS_SECRET,
    keep: ['aws configure set', 'aws_secret_access_key'],
  },
  {
    name: 'aws access key id by shape',
    input: `echo ${AWS_KEY_ID} >> notes.txt`,
    secret: AWS_KEY_ID,
    keep: ['echo', 'notes.txt'],
  },
  {
    name: 'slack token in a header',
    input: `curl -X POST https://hooks.slack.com/services/T0/B0 -H "X-Token: ${SLACK}"`,
    secret: SLACK,
    keep: ['hooks.slack.com'],
  },
  {
    name: 'JWT in a cookie',
    input: `curl -H "Cookie: session=${JWT}" https://x.example`,
    secret: JWT,
    keep: ['curl', 'https://x.example'],
  },
  {
    name: 'google api key in a query string',
    input: `curl "https://maps.googleapis.com/maps/api/geocode/json?key=${GOOGLE}"`,
    secret: GOOGLE,
    keep: ['maps.googleapis.com'],
  },
  {
    name: 'gitlab token flag',
    input: `glab auth login --token ${GITLAB}`,
    secret: GITLAB,
    keep: ['glab auth login'],
  },
  {
    name: 'inline private key',
    input:
      'echo "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----" > id',
    secret: 'b3BlbnNzaC1rZXktdjEAAAAA',
    keep: ['echo'],
  },
];

test('secrets are removed from recorded text', () => {
  for (const c of SECRETS) {
    const out = redact(c.input);
    assert.equal(out.includes(c.secret), false, `${c.name}: secret survived → ${out}`);
    assert.match(out, /\[redacted:/, `${c.name}: nothing was marked as redacted`);
  }
});

test('the command stays readable after redaction', () => {
  for (const c of SECRETS) {
    const out = redact(c.input);
    for (const fragment of c.keep) {
      assert.ok(out.includes(fragment), `${c.name}: lost context "${fragment}" → ${out}`);
    }
  }
});

/**
 * False positives are not free: an auditor reading a log needs digests, commit
 * hashes and paths intact. These must pass through untouched.
 */
const KEEP_VERBATIM = [
  'git commit -m "fix auth"',
  'git checkout 3e1a9c0f4b2d8e7a6c5b4a39281706f5e4d3c2b1',
  'npm test -- --grep "token refresh"',
  'cargo test --all-features',
  'sha256:27008480afd7930c476753454b59bc78a4e726a18ed5d2f9322dfcdabdafa2c3',
  'curl https://api.example.com/v1/models',
  'cat src/auth/token_service.rs',
  'grep -rn "password" src/',
  'kubectl apply -f k8s/deployment.yaml',
  'echo "my key is in the vault"',
  'ssh-keygen -lf ~/.ssh/id_ed25519.pub',
  'psql -h db.internal -U admin',
  'aws s3 ls s3://bucket/key/path',
];

test('ordinary commands are not mangled', () => {
  for (const command of KEEP_VERBATIM) {
    assert.equal(redact(command), command, `redaction altered: ${command}`);
  }
});

test('redaction is idempotent, so re-recording cannot nest markers', () => {
  for (const c of SECRETS) {
    const once = redact(c.input);
    assert.equal(redact(once), once, c.name);
  }
});

test('the flag reports whether anything was redacted', () => {
  assert.deepEqual(redactWithFlag('npm test'), { value: 'npm test', redacted: false });

  const dirty = redactWithFlag('psql --password=hunter2');
  assert.equal(dirty.redacted, true);
  assert.equal(dirty.value.includes('hunter2'), false);
});

test('empty and non-string input is handled without throwing', () => {
  assert.equal(redact(undefined), '');
  assert.equal(redact(null), '');
  assert.equal(redact(''), '');
  assert.equal(redact(42), '42');
});
