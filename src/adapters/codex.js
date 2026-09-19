/**
 * Codex CLI hook adapter.
 *
 * Codex runs lifecycle hooks with the same protocol as Claude Code: a JSON
 * object on stdin, a JSON object on stdout, `hookSpecificOutput` with a
 * `permissionDecision`, and exit code 2 as the plain-text block. Hooks live in
 * `.codex/hooks.json` and are enabled by default in current Codex releases.
 *
 * Two Codex-specific rules shape this file:
 *
 *   1. PreToolUse does not support `ask`: Codex parses it but marks the hook
 *      as failed, and a failed hook does not block. Returning `ask` would
 *      therefore let the action run. Provenant resolves `ask` itself instead:
 *      it blocks, and a human clears that exact action with
 *      `provenant approve <id>` before the agent retries.
 *
 *   2. An `allow` is expressed by staying silent, not by returning
 *      `permissionDecision: "allow"`. Silence leaves Codex's own approval
 *      policy and sandbox in force; an explicit allow could skip them.
 *      Provenant narrows what Codex permits and never widens it.
 *
 * Stop fires at the end of every turn, so it checkpoints rather than ends the
 * session; SessionEnd ends it.
 */

import {
  gateToolCall,
  recordOutcome,
  recordPrompt,
  startSession,
  endSession,
  checkpointSession,
} from '../gate.js';
import { normalize, renderResponse, isErrorResponse, approvalMessage } from './common.js';

const HARNESS = 'codex';

/**
 * @param {string} event
 * @param {object} payload
 * @returns {{stdout: object|null, exitCode: number, stderr?: string}}
 */
export function handle(event, payload) {
  const p = normalize(payload);
  const common = { harnessSessionId: p.harnessSessionId, harness: HARNESS, cwd: p.cwd };

  switch (event) {
    case 'session-start':
      startSession({ ...common, model: p.model });
      return silent();

    case 'prompt':
      recordPrompt({ ...common, prompt: p.prompt });
      return silent();

    case 'pre-tool': {
      if (!p.tool) return silent();
      const d = gateToolCall({ ...common, tool: p.tool, input: p.input, askMode: 'approval' });
      return preToolResponse(d);
    }

    case 'post-tool':
      if (!p.tool) return silent();
      recordOutcome({
        ...common,
        tool: p.tool,
        input: p.input,
        output: renderResponse(p.response),
        ok: !isErrorResponse(p.response),
      });
      return silent();

    case 'stop':
      checkpointSession(common);
      return silent();

    case 'session-end':
      endSession({ ...common, reason: p.reason });
      return silent();

    default:
      throw new Error(`unknown Codex hook event: ${event}`);
  }
}

function silent() {
  return { stdout: null, exitCode: 0 };
}

function preToolResponse(decision) {
  if (decision.effect === 'allow') return silent();

  const reason =
    decision.effect === 'ask'
      ? approvalMessage(decision)
      : `Blocked by Provenant [${decision.class}]: ${decision.reason}`;

  if (process.env.PROVENANT_HOOK_MODE === 'exitcode') {
    return { stdout: null, exitCode: 2, stderr: reason };
  }

  return {
    stdout: {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: reason,
      },
    },
    exitCode: 0,
  };
}

/**
 * Hook configuration for `.codex/hooks.json`. `commandWindows` is set to the
 * same command so the hook resolves on Windows too, where npm installs a
 * `provenant.cmd` shim.
 */
export function hookConfig(binary = 'provenant') {
  const cmd = (event) => ({
    type: 'command',
    command: `${binary} hook codex ${event}`,
    commandWindows: `${binary} hook codex ${event}`,
    timeout: 30,
  });
  return {
    SessionStart: [{ hooks: [cmd('session-start')] }],
    UserPromptSubmit: [{ hooks: [cmd('prompt')] }],
    PreToolUse: [{ matcher: '*', hooks: [cmd('pre-tool')] }],
    PostToolUse: [{ matcher: '*', hooks: [cmd('post-tool')] }],
    Stop: [{ hooks: [cmd('stop')] }],
    SessionEnd: [{ hooks: [cmd('session-end')] }],
  };
}
