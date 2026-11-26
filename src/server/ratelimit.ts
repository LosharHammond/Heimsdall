/** In-memory fixed-window limiter. Correct for a single instance only; use a shared store when scaling out. */
export class RateLimiter {
  private hits = new Map<string, { count: number; resetAt: number }>();
  constructor(
    private max: number,
    private windowMs: number,
  ) {}
  check(key: string, now = Date.now()): { ok: boolean; retryAfterSec: number } {
    if (this.hits.size > 20000) this.sweep(now);
    const h = this.hits.get(key);
    if (!h || h.resetAt <= now) {
      this.hits.set(key, { count: 1, resetAt: now + this.windowMs });
      return { ok: true, retryAfterSec: 0 };
    }
    h.count++;
    return { ok: h.count <= this.max, retryAfterSec: Math.ceil((h.resetAt - now) / 1000) };
  }
  private sweep(now: number) {
    for (const [k, v] of this.hits) if (v.resetAt <= now) this.hits.delete(k);
  }
}
