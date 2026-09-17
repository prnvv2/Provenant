/**
 * Canonical JSON serialisation (RFC 8785 JCS subset).
 *
 * Two parties must produce identical bytes for the same logical value, or every
 * hash and signature over that value disagrees. This implements the subset the
 * event model needs:
 *
 *   - object keys sorted by UTF-16 code unit
 *   - no insignificant whitespace
 *   - strings and numbers serialised by JSON.stringify (ES6 number format)
 *   - undefined / function / symbol values rejected, not silently dropped
 *   - non-finite numbers rejected
 *
 * Not implemented from RFC 8785: nothing in the event model uses lone
 * surrogates or numbers outside the IEEE-754 double range, so those are
 * rejected rather than canonicalised. See spec/canonicalisation.md.
 */

const ALLOWED_SCALARS = new Set(['string', 'number', 'boolean']);

/** @param {unknown} value @returns {string} */
export function canonicalize(value) {
  return serialize(value, []);
}

/** @param {unknown} value @returns {Buffer} */
export function canonicalBytes(value) {
  return Buffer.from(canonicalize(value), 'utf8');
}

function serialize(value, path) {
  if (value === null) return 'null';

  const t = typeof value;

  if (t === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError(`non-finite number at ${fmtPath(path)}`);
    }
    // JSON.stringify uses the ES6 Number::toString algorithm, which is what
    // RFC 8785 specifies for number serialisation.
    return JSON.stringify(value);
  }

  if (ALLOWED_SCALARS.has(t)) return JSON.stringify(value);

  if (Array.isArray(value)) {
    const items = value.map((v, i) => serialize(v, [...path, i]));
    return `[${items.join(',')}]`;
  }

  if (t === 'object') {
    if (value instanceof Date) {
      throw new TypeError(
        `Date at ${fmtPath(path)}: convert to an ISO-8601 string before canonicalising`,
      );
    }
    const keys = Object.keys(value).sort(compareCodeUnits);
    const parts = [];
    for (const key of keys) {
      const v = value[key];
      if (v === undefined) {
        throw new TypeError(`undefined value at ${fmtPath([...path, key])}`);
      }
      parts.push(`${JSON.stringify(key)}:${serialize(v, [...path, key])}`);
    }
    return `{${parts.join(',')}}`;
  }

  throw new TypeError(`unsupported ${t} at ${fmtPath(path)}`);
}

/** Sort by UTF-16 code unit, which is what `<` does on JS strings. */
function compareCodeUnits(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

function fmtPath(path) {
  return path.length === 0 ? '$' : `$.${path.join('.')}`;
}
