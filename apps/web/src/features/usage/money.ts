/**
 * Money helpers for the usage surface.
 *
 * The API stores costs as integer minor units. These helpers never turn a
 * missing amount into zero and never recalculate a cost from tokens or a
 * current price. Formatting is deliberately deterministic for the control
 * plane and keeps the currency visible at provenance boundaries.
 */

export interface MoneyValue {
  minor: number;
  currency: string;
}

export interface MoneyFormatOptions {
  /** Append the ISO currency code after the formatted amount. */
  showCode?: boolean;
  /** Use a compact magnitude for large dashboard values. */
  compact?: boolean;
}

const DEFAULT_CURRENCY = "USD";

/** Common currencies whose minor unit is not two decimal places. */
const CURRENCY_FRACTION_DIGITS: Record<string, number> = {
  BHD: 3,
  BIF: 0,
  CLP: 0,
  DJF: 0,
  GNF: 0,
  IQD: 3,
  ISK: 0,
  JOD: 3,
  JPY: 0,
  KMF: 0,
  KRW: 0,
  KWD: 3,
  LYD: 3,
  OMR: 3,
  PYG: 0,
  RWF: 0,
  TND: 3,
  UGX: 0,
  UYW: 4,
  VND: 0,
  VUV: 0,
  XAF: 0,
  XOF: 0,
  XPF: 0,
};

export function isCurrencyCode(value: string | null | undefined): value is string {
  const normalized = value?.trim().toUpperCase();
  return Boolean(normalized && /^[A-Z]{3,12}$/.test(normalized));
}

export function normalizeCurrency(value: string | null | undefined): string {
  const normalized = value?.trim().toUpperCase();
  return isCurrencyCode(normalized) ? normalized : DEFAULT_CURRENCY;
}

export function currencyFractionDigits(value: string | null | undefined): number {
  const currency = normalizeCurrency(value);
  const known = CURRENCY_FRACTION_DIGITS[currency];
  if (known !== undefined) return known;
  try {
    return (
      new Intl.NumberFormat("en-US", {
        style: "currency",
        currency,
        currencyDisplay: "code",
      }).resolvedOptions().maximumFractionDigits ?? 2
    );
  } catch {
    return 2;
  }
}

export function isMinorUnitAmount(value: number | null | undefined): value is number {
  return typeof value === "number" && Number.isSafeInteger(value);
}

/**
 * Format an integer minor-unit amount. A missing or unsafe amount is shown as
 * an em dash rather than being coerced into a misleading zero.
 */
export function formatMinorUnits(
  minor: number | null | undefined,
  currency: string | null | undefined,
  options: MoneyFormatOptions = {},
): string {
  if (!isMinorUnitAmount(minor)) return "—";
  if (!isCurrencyCode(currency)) return options.showCode ? "Currency unavailable" : "—";

  const code = currency.trim().toUpperCase();
  const fractionDigits = currencyFractionDigits(code);
  const divisor = 10 ** fractionDigits;
  const major = minor / divisor;

  if (options.compact && Math.abs(major) >= 1_000_000) {
    const compact = new Intl.NumberFormat("en-US", {
      notation: "compact",
      maximumFractionDigits: 1,
    }).format(major);
    return options.showCode ? `${compact} ${code}` : compact;
  }

  try {
    const formatted = new Intl.NumberFormat("en-US", {
      style: "currency",
      currency: code,
      currencyDisplay: "symbol",
      minimumFractionDigits: fractionDigits,
      maximumFractionDigits: fractionDigits,
    }).format(major);
    return options.showCode ? `${formatted} ${code}` : formatted;
  } catch {
    // The ISO code is already validated above; this is only a defensive path
    // for runtimes with incomplete Intl currency data.
    return `${code} ${(minor / divisor).toFixed(fractionDigits)}`;
  }
}

export function formatMoney(
  value: MoneyValue | null | undefined,
  options: MoneyFormatOptions = {},
): string {
  if (!value || !isMinorUnitAmount(value.minor)) return "—";
  return formatMinorUnits(value.minor, value.currency, options);
}

/** Add bounded integer minor units without silently overflowing. */
export function addMinorUnits(values: readonly (number | null | undefined)[]): number | null {
  let total = 0;
  for (const value of values) {
    if (value === null || value === undefined) continue;
    if (!isMinorUnitAmount(value)) return null;
    total += value;
    if (!Number.isSafeInteger(total)) return null;
  }
  return total;
}

export function formatPercent(numerator: number, denominator: number): string {
  if (!Number.isFinite(numerator) || !Number.isFinite(denominator) || denominator <= 0) return "—";
  const percentage = Math.max(0, (numerator / denominator) * 100);
  if (percentage >= 10) return `${Math.round(percentage)}%`;
  return `${percentage.toFixed(1)}%`;
}
