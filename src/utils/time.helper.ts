export type TimeUnit = 's' | 'm' | 'h' | 'd';

/**
 * Converts a number + time unit into seconds.
 * Defaults to days if unit not provided.
 */
export function toSeconds(value: number, unit: TimeUnit = 'd'): number {
  switch (unit) {
    case 's': return value;
    case 'm': return value * 60;
    case 'h': return value * 60 * 60;
    case 'd': return value * 24 * 60 * 60;
    default: throw new Error(`Unsupported time unit: ${unit}`);
  }
}