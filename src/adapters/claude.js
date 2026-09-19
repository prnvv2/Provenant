/**
 * Claude Code hook adapter.
 *
 * Claude Code runs hook commands with a JSON object on stdin and reads a JSON
 * object from stdout. For PreToolUse it honours a permission decision of
 * allow / deny / ask.
 *
 * Hook payload and response shapes are owned by Claude Code and change between
 * versions, so everything version-specific lives in this file and is covered by
 * recorded fixtures in test/fixtures/claude/. If the response shape changes,
 * PROVENANT_HOOK_MODE=exitcode falls back to the exit-code protocol (2 blocks).
 */

import { gateToolCall, recordOutcome, recordPrompt, startSession, endSession } from '../gate.js';
import { normalize, renderResponse, isErrorResponse, approvalMessage } from './common.js';

export { normalize };

/**
 * @param {string} event hook event name
 * @param {object} payload
 * @returns {{stdout: object|null, exitCode: number, stderr?: string}}
 */
export function handle(event, payload) {
  const p = normalize(payload);
  const common = { harnessSessionId: p.harnessSessionId, harness: 'claude-code', cwd: p.cwd };

  switch (event) {
    case 'session-start': {
      const r = startSession({ ...common, model: p.model });
      return { stdout: { continue: true, provenant: r }, exitCode: 0 };
    }

    case 'prompt': {
      const r = recordPrompt({ ...common, prompt: p.prompt });
      return { stdout: { continue: true, provenant: r }, exitCode: 0 };
    }

    case 'pre-tool': {
      if (!p.tool) {
        return { stdout: { continue: true }, exitCode: 0 };
      }
      // The exit-code protocol cannot express "ask", so in that mode an
      // escalation becomes a block that a human clears with `provenant approve`.
      const exitcodeMode = process.env.PROVENANT_HOOK_MODE === 'exitcode';
      const d = gateToolCall({
        ...common,
        tool: p.tool,
        input: p.input,
        askMode: exitcodeMode ? 'approval' : 'native',
      });
      return preToolResponse(d);
    }

    case 'post-tool': {
      if (!p.tool) return { stdout: { continue: true }, exitCode: 0 };
      const r = recordOutcome({
        ...common,
        tool: p.tool,
        input: p.input,
        output: renderResponse(p.response),
        ok: !isErrorResponse(p.response),
      });
      return { stdout: { continue: true, provenant: r }, exitCode: 0 };
    }

    case 'stop':
    case 'session-end': {
      const r = endSession({ ...common, reason: p.reason });
      return {
        stdout: {
          continue: true,
          provenant: { session: r.session, root: r.checkpoint.root, size: r.checkpoint.size },
        },
        exitCode: 0,
      };
    }

    default:
      throw new Error(`unknown Claude Code hook event: ${event}`);
  }
}

function preToolResponse(decision) {
  const detail = `${decision.effect === 'deny' ? 'Blocked' : 'Review'} by Provenant [${decision.class}]: ${decision.reason}`;

  if (process.env.PROVENANT_HOOK_MODE === 'exitcode') {
    // Exit code 2 blocks the call and feeds stderr back to the model. An
    // unapproved `ask` blocks too: letting it through would fail open.
    if (decision.effect === 'deny') return { stdout: null, exitCode: 2, stderr: detail };
    if (decision.effect === 'ask') return { stdout: null, exitCode: 2, stderr: approvalMessage(decision) };
    return { stdout: null, exitCode: 0 };
  }

  return {
    stdout: {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: decision.effect,
        permissionDecisionReason:
          decision.effect === 'allow'
            ? `Provenant: allowed [${decision.class}]`
            : detail,
      },
      provenant: {
        session: decision.session,
        event: decision.event,
        class: decision.class,
        policy: decision.policy,
        taint: decision.taint,
      },
    },
    exitCode: 0,
  };
}

/** Hook configuration written by `provenant init`. */
export function hookConfig(binary = 'provenant') {
  const cmd = (event) => ({ type: 'command', command: `${binary} hook claude ${event}` });
  return {
    SessionStart: [{ hooks: [cmd('session-start')] }],
    UserPromptSubmit: [{ hooks: [cmd('prompt')] }],
    PreToolUse: [{ matcher: '*', hooks: [cmd('pre-tool')] }],
    PostToolUse: [{ matcher: '*', hooks: [cmd('post-tool')] }],
    Stop: [{ hooks: [cmd('stop')] }],
  };
}
