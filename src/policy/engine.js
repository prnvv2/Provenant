/**
 * Policy engine.
 *
 * Rules are declarative JSON, evaluated in order: the first rule whose
 * conditions all match decides. No rule matching means `defaultEffect`.
 *
 * Why not Cedar in v0.1: Cedar has no native "ask" effect, so it needs an
 * annotation convention plus a schema and entity model before it can express
 * these rules. That is worth doing once the class set stops moving; the engine
 * boundary here is deliberately narrow so it can be swapped.
 * See docs/adr/0005-policy-engine.md.
 */

import { readFileSync, existsSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { canonicalBytes } from '../core/canonical.js';
import { digestRef } from '../core/hash.js';
import { paths } from '../store/paths.js';

export const EFFECTS = Object.freeze(['allow', 'ask', 'deny']);

/** Taint lattice, most to least trusted. */
export const TAINT_ORDER = Object.freeze(['trusted', 'internal', 'external', 'untrusted-exec']);

export function taintRank(t) {
  const i = TAINT_ORDER.indexOf(t);
  return i === -1 ? TAINT_ORDER.length - 1 : i;
}

/** Lower of two taint labels. */
export function lowerTaint(a, b) {
  return taintRank(a) >= taintRank(b) ? a : b;
}

/**
 * Load the active policy: explicit path, else the store's policy.json, else the
 * bundled default.
 *
 * @param {string} [file]
 * @returns {{policy: object, source: string, digest: string}}
 */
export function loadPolicy(file) {
  const candidates = [file, process.env.PROVENANT_POLICY, paths.policy(), bundledPolicyPath()].filter(
    Boolean,
  );

  for (const candidate of candidates) {
    let stat;
    try {
      stat = statSync(candidate);
    } catch {
      continue;
    }

    // Parsing and digesting the policy on every call is wasted work in a
    // long-lived process. Keyed on mtime so an edited policy is picked up.
    const key = `${candidate}:${stat.mtimeMs}:${stat.size}`;
    const hit = cache.get(key);
    if (hit) return hit;

    const policy = JSON.parse(readFileSync(candidate, 'utf8').replace(/^﻿/, ''));
    validatePolicy(policy, candidate);
    const loaded = { policy, source: candidate, digest: digestRef(canonicalBytes(policy)) };
    cache.clear();
    cache.set(key, loaded);
    return loaded;
  }
  throw new Error('no policy found: run `provenant init` or pass --policy <file>');
}

const cache = new Map();

/** Drop the policy cache. Tests and long-lived processes use this. */
export function clearPolicyCache() {
  cache.clear();
}

/** Absolute path to the policy shipped inside the package. */
export function bundledPolicyPath() {
  return fileURLToPath(new URL('../../policies/default.json', import.meta.url));
}

export function validatePolicy(policy, source = '<inline>') {
  if (!policy || typeof policy !== 'object') throw new Error(`${source}: policy must be an object`);
  if (!Array.isArray(policy.rules)) throw new Error(`${source}: policy.rules must be an array`);
  if (policy.defaultEffect && !EFFECTS.includes(policy.defaultEffect)) {
    throw new Error(`${source}: defaultEffect must be one of ${EFFECTS.join(', ')}`);
  }
  for (const [i, rule] of policy.rules.entries()) {
    if (!rule.id) throw new Error(`${source}: rule ${i} has no id`);
    if (!EFFECTS.includes(rule.effect)) {
      throw new Error(`${source}: rule ${rule.id} has effect ${rule.effect}`);
    }
    if (rule.classes && !Array.isArray(rule.classes)) {
      throw new Error(`${source}: rule ${rule.id} classes must be an array`);
    }
  }
  return true;
}

/**
 * Evaluate one action against a policy.
 *
 * @param {object} args
 * @param {object} args.policy
 * @param {string} args.actionClass
 * @param {string} [args.taint]
 * @param {string} [args.resource]
 * @returns {{effect: string, policy: string, reason: string}}
 */
export function evaluate({ policy, actionClass, taint = 'trusted', resource = '' }) {
  for (const rule of policy.rules) {
    if (!matches(rule, { actionClass, taint, resource })) continue;
    return {
      effect: rule.effect,
      policy: rule.id,
      reason: rule.reason || `${rule.effect} by rule ${rule.id}`,
    };
  }
  return {
    effect: policy.defaultEffect || 'ask',
    policy: 'default',
    reason: `no rule matched ${actionClass}; default effect applied`,
  };
}

function matches(rule, { actionClass, taint, resource }) {
  if (rule.classes && !rule.classes.includes(actionClass)) return false;

  // whenTaintAtOrBelow: rule applies once trust has dropped to that level.
  if (rule.whenTaintAtOrBelow && taintRank(taint) < taintRank(rule.whenTaintAtOrBelow)) {
    return false;
  }
  if (rule.whenTaintAbove && taintRank(taint) >= taintRank(rule.whenTaintAbove)) {
    return false;
  }
  if (rule.resourceMatches) {
    let re;
    try {
      re = new RegExp(rule.resourceMatches, 'i');
    } catch {
      return false;
    }
    if (!re.test(String(resource))) return false;
  }
  if (rule.resourceNotMatches) {
    let re;
    try {
      re = new RegExp(rule.resourceNotMatches, 'i');
    } catch {
      return false;
    }
    if (re.test(String(resource))) return false;
  }
  return true;
}

/**
 * Decide, combining classification and policy. Kept separate from I/O so it can
 * be table-tested.
 *
 * @param {object} args
 * @param {object} args.policy
 * @param {{class: string, resource?: string}} args.classification
 * @param {string} args.taint
 * @returns {{effect: string, policy: string, reason: string, class: string}}
 */
export function decide({ policy, classification, taint }) {
  const res = evaluate({
    policy,
    actionClass: classification.class,
    taint,
    resource: classification.resource,
  });
  return { ...res, class: classification.class };
}
