/**
 * Helpers shared by harness adapters.
 *
 * Claude Code and Codex send near-identical hook payloads (snake_case), and the
 * OpenCode plugin forwards its events in the same shape, so one normaliser
 * serves all three. Anything genuinely harness-specific stays in that
 * harness's adapter.
 */

/** @param {object} payload raw hook JSON */
export function normalize(payload = {}) {
  const p = payload && typeof payload === 'object' ? payload : {};
  return {
    harnessSessionId: p.session_id ?? p.sessionId ?? p.sessionID ?? null,
    cwd: p.cwd ?? p.workspace_root ?? p.directory ?? process.cwd(),
    tool: p.tool_name ?? p.toolName ?? p.tool ?? null,
    input: p.tool_input ?? p.toolInput ?? p.args ?? {},
    response: p.tool_response ?? p.toolResponse ?? undefined,
    prompt: p.prompt ?? p.user_prompt ?? '',
    reason: p.reason ?? p.stop_reason ?? p.source ?? 'stop',
    model: typeof p.model === 'object' && p.model !== null ? p.model.id ?? p.model.modelID : p.model,
  };
}

/** Tool output as a string, for digesting. Never stored. */
export function renderResponse(response) {
  if (response === undefined || response === null) return undefined;
  if (typeof response === 'string') return response;
  try {
    return JSON.stringify(response);
  } catch {
    return String(response);
  }
}

export function isErrorResponse(response) {
  if (!response || typeof response !== 'object') return false;
  return (
    response.success === false ||
    response.is_error === true ||
    response.isError === true ||
    response.interrupted === true ||
    (typeof response.exit_code === 'number' && response.exit_code !== 0) ||
    (typeof response.exitCode === 'number' && response.exitCode !== 0)
  );
}

/**
 * The message an agent sees when an action needs approval it cannot get from
 * its own harness. Written to be relayed to the user as-is.
 */
export function approvalMessage(decision) {
  return (
    `Provenant: this action needs human approval [${decision.class}]: ${decision.reason} ` +
    `Ask the user to review it and run \`provenant approve ${decision.approval}\` in their own terminal, ` +
    'then retry exactly the same action. Do not try to run the approval yourself; it will be refused.'
  );
}
