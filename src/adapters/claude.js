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

/** @param {object} payload raw hook JSON */
export function normalize(payload = {}) {
  return {
    harnessSessionId: payload.session_id ?? payload.sessionId ?? null,
    cwd: payload.cwd ?? payload.workspace_root ?? process.cwd(),
    tool: payload.tool_name ?? payload.toolName ?? null,
    input: payload.tool_input ?? payload.toolInput ?? {},
    response: payload.tool_response ?? payload.toolResponse ?? undefined,
    prompt: payload.prompt ?? payload.user_prompt ?? '',
    reason: payload.reason ?? payload.stop_reason ?? 'stop',
    model: payload.model?.id ?? payload.model ?? undefined,
  };
}

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
      const d = gateToolCall({ ...common, tool: p.tool, input: p.input });
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
    // Exit code 2 blocks the call and feeds stderr back to the model.
    return decision.effect === 'deny'
      ? { stdout: null, exitCode: 2, stderr: detail }
      : { stdout: null, exitCode: 0 };
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

function renderResponse(response) {
  if (response === undefined || response === null) return undefined;
  if (typeof response === 'string') return response;
  try {
    return JSON.stringify(response);
  } catch {
    return String(response);
  }
}

function isErrorResponse(response) {
  if (!response) return false;
  if (typeof response === 'object') {
    if (response.success === false) return true;
    if (response.is_error === true || response.isError === true) return true;
    if (typeof response.interrupted === 'boolean' && response.interrupted) return true;
  }
  return false;
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
