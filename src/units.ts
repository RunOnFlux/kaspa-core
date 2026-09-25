import { MAX_SOMPI, SOMPI_PER_KASPA } from './constants.js';
import { invalidInput } from './errors.js';

const DECIMAL_RE = /^(\d+)(?:\.(\d{1,8}))?$/;

/**
 * Parse a KAS amount written as a decimal string into sompi, exactly.
 * Accepts at most 8 fractional digits and never goes through floating point,
 * so `"0.1"` is exactly 10,000,000 sompi. Rejects signs, exponents, spaces,
 * thousands separators and values above MAX_SOMPI.
 */
export function kaspaToSompi(amount: string): bigint {
  if (typeof amount !== 'string') throw invalidInput('amount must be a string');
  const m = DECIMAL_RE.exec(amount);
  if (!m)
    throw invalidInput(
      'amount must be a plain decimal with at most 8 fractional digits',
    );
  const whole = BigInt(m[1] ?? '0');
  const frac = BigInt((m[2] ?? '').padEnd(8, '0'));
  const sompi = whole * SOMPI_PER_KASPA + frac;
  if (sompi > MAX_SOMPI)
    throw invalidInput('amount exceeds the maximum supply');
  return sompi;
}

/** Format sompi as a KAS decimal string without trailing zeros (`"1.5"`, `"0.00000001"`). */
export function sompiToKaspa(sompi: bigint): string {
  if (typeof sompi !== 'bigint' || sompi < 0n)
    throw invalidInput('sompi must be a non-negative bigint');
  const whole = sompi / SOMPI_PER_KASPA;
  const frac = (sompi % SOMPI_PER_KASPA)
    .toString()
    .padStart(8, '0')
    .replace(/0+$/, '');
  return frac.length > 0 ? `${whole.toString()}.${frac}` : whole.toString();
}
