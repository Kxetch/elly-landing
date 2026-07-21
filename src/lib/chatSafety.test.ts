import { describe, expect, it } from 'vitest';
import {
  SYSTEM_PROMPT,
  checkDistributedRateLimits,
  checkSoftHourlyQuota,
  getClientIp,
  isLongEnough,
  isValidMessageField,
  sanitizeInput,
  type RateLimitBinding,
} from './chatSafety';

function fakeBinding(success: boolean): RateLimitBinding & { calls: Array<{ key: string }> } {
  const calls: Array<{ key: string }> = [];
  return {
    calls,
    async limit(options) {
      calls.push(options);
      return { success };
    },
  };
}

describe('getClientIp', () => {
  it('uses CF-Connecting-IP, the header Cloudflare itself sets and a client cannot forge', () => {
    const req = new Request('https://example.com/api/chat', {
      headers: { 'cf-connecting-ip': '203.0.113.7' },
    });
    expect(getClientIp(req)).toBe('203.0.113.7');
  });

  it('trims incidental whitespace', () => {
    const req = new Request('https://example.com/api/chat', {
      headers: { 'cf-connecting-ip': '  203.0.113.7  ' },
    });
    expect(getClientIp(req)).toBe('203.0.113.7');
  });

  it(
    'regression: NEVER falls back to X-Forwarded-For -- a client-controlled header. ' +
      'The previous version of this code used forwarded.split(",")[0], which reads ' +
      'the attacker-supplied value (Cloudflare appends its own trusted IP, it does ' +
      'not replace what the client already sent), letting a scripted attacker send a ' +
      'fresh X-Forwarded-For on every request and get a fresh rate-limit bucket every ' +
      'time -- verified live during this review as a complete bypass of the 5/hour cap.',
    () => {
      const req = new Request('https://example.com/api/chat', {
        headers: { 'x-forwarded-for': '6.6.6.6, 203.0.113.7' },
      });
      expect(getClientIp(req)).toBe('unknown');
    },
  );

  it('returns "unknown" (one shared bucket) when neither header is present, rather than inventing a spoofable substitute', () => {
    const req = new Request('https://example.com/api/chat');
    expect(getClientIp(req)).toBe('unknown');
  });
});

describe('sanitizeInput', () => {
  it('strips angle brackets', () => {
    expect(sanitizeInput('<script>alert(1)</script>')).toBe('scriptalert(1)/script');
  });

  it('strips control characters', () => {
    expect(sanitizeInput('hello\x00\x01\x08world')).toBe('helloworld');
  });

  it('collapses internal whitespace runs (including newlines/tabs) to a single space', () => {
    expect(sanitizeInput('hello\n\n\tworld   again')).toBe('hello world again');
  });

  it('trims leading/trailing whitespace', () => {
    expect(sanitizeInput('   hello world   ')).toBe('hello world');
  });

  it('truncates to 500 characters', () => {
    const long = 'a'.repeat(1000);
    expect(sanitizeInput(long)).toHaveLength(500);
  });

  it('leaves an ordinary question untouched', () => {
    expect(sanitizeInput('How much does elly cost per month?')).toBe(
      'How much does elly cost per month?',
    );
  });
});

describe('isValidMessageField', () => {
  it('accepts a non-empty string', () => {
    expect(isValidMessageField('hi')).toBe(true);
  });

  it.each([
    ['empty string', ''],
    ['whitespace-only string', '   '],
    ['undefined', undefined],
    ['null', null],
    ['a number', 42],
    ['an object', { message: 'hi' }],
    ['an array', ['hi']],
  ])('rejects %s', (_label, value) => {
    expect(isValidMessageField(value)).toBe(false);
  });
});

describe('isLongEnough', () => {
  it('rejects fewer than 3 characters', () => {
    expect(isLongEnough('hi')).toBe(false);
    expect(isLongEnough('')).toBe(false);
  });

  it('accepts 3 or more characters', () => {
    expect(isLongEnough('hey')).toBe(true);
    expect(isLongEnough('how much does elly cost')).toBe(true);
  });
});

describe('checkSoftHourlyQuota', () => {
  it('the first request from a key gets 4 remaining (of a max 5)', () => {
    const store = new Map();
    expect(checkSoftHourlyQuota(store, '1.2.3.4', 0).remaining).toBe(4);
  });

  it('decrements on each subsequent request within the window', () => {
    const store = new Map();
    checkSoftHourlyQuota(store, '1.2.3.4', 0);
    checkSoftHourlyQuota(store, '1.2.3.4', 1000);
    expect(checkSoftHourlyQuota(store, '1.2.3.4', 2000).remaining).toBe(2);
  });

  it('never goes below 0 even if called more than the max', () => {
    const store = new Map();
    for (let i = 0; i < 10; i++) checkSoftHourlyQuota(store, '1.2.3.4', i);
    expect(checkSoftHourlyQuota(store, '1.2.3.4', 11).remaining).toBe(0);
  });

  it('resets once the hour window has elapsed', () => {
    const store = new Map();
    checkSoftHourlyQuota(store, '1.2.3.4', 0);
    checkSoftHourlyQuota(store, '1.2.3.4', 1000);
    const oneHourLater = 60 * 60 * 1000 + 1;
    expect(checkSoftHourlyQuota(store, '1.2.3.4', oneHourLater).remaining).toBe(4);
  });

  it('tracks different keys independently', () => {
    const store = new Map();
    checkSoftHourlyQuota(store, 'visitor-a', 0);
    checkSoftHourlyQuota(store, 'visitor-a', 0);
    expect(checkSoftHourlyQuota(store, 'visitor-b', 0).remaining).toBe(4);
  });
});

describe('checkDistributedRateLimits', () => {
  it('allows the request when both the per-visitor and global limiters succeed', async () => {
    const perVisitor = fakeBinding(true);
    const global = fakeBinding(true);
    const result = await checkDistributedRateLimits({ perVisitor, global }, '1.2.3.4');
    expect(result).toEqual({ allowed: true, reason: null });
  });

  it('blocks and reports "per-visitor" when only the per-visitor limiter fails', async () => {
    const perVisitor = fakeBinding(false);
    const global = fakeBinding(true);
    const result = await checkDistributedRateLimits({ perVisitor, global }, '1.2.3.4');
    expect(result).toEqual({ allowed: false, reason: 'per-visitor' });
  });

  it(
    'blocks and reports "global" when only the sitewide limiter fails -- this is the ' +
      'backstop against many different real visitors (a botnet, a rotating proxy) each ' +
      'individually staying under their own per-visitor limit',
    async () => {
      const perVisitor = fakeBinding(true);
      const global = fakeBinding(false);
      const result = await checkDistributedRateLimits({ perVisitor, global }, '1.2.3.4');
      expect(result).toEqual({ allowed: false, reason: 'global' });
    },
  );

  it('calls the per-visitor limiter with the visitor key, and the global limiter with a fixed key -- never the visitor key', async () => {
    const perVisitor = fakeBinding(true);
    const global = fakeBinding(true);
    await checkDistributedRateLimits({ perVisitor, global }, 'visitor-ip-123');
    expect(perVisitor.calls).toEqual([{ key: 'visitor-ip-123' }]);
    expect(global.calls).toEqual([{ key: 'sitewide' }]);
    expect(global.calls[0].key).not.toBe('visitor-ip-123');
  });

  it('checks both limiters even when one has already failed, so a single request only ever costs two fast binding calls, not a short-circuit that skips accounting for the other', async () => {
    const perVisitor = fakeBinding(false);
    const global = fakeBinding(true);
    await checkDistributedRateLimits({ perVisitor, global }, '1.2.3.4');
    expect(perVisitor.calls).toHaveLength(1);
    expect(global.calls).toHaveLength(1);
  });
});

describe('SYSTEM_PROMPT accuracy regressions', () => {
  // These are static content assertions, not a substitute for actually
  // exercising the model (see the manual live-QA log in the PR/commit
  // description) -- but they pin down the exact, previously-wrong
  // claims this review found and fixed, so a future edit can't
  // silently reintroduce them.

  it('states the real, single $5/month price', () => {
    expect(SYSTEM_PROMPT).toContain('$5/month');
  });

  it('never asserts the old, invented "$5-15/mo" price range as fact (it may still mention it as a negative example to steer the model away from)', () => {
    expect(SYSTEM_PROMPT).not.toMatch(/patreon \(\$5-15/i);
    expect(SYSTEM_PROMPT).not.toMatch(/\$15\/m/);
  });

  it('does not claim the full app is freely self-hostable (only the backend is open source)', () => {
    expect(SYSTEM_PROMPT).not.toMatch(/self-host \(free\)/i);
  });

  it('does not claim calendar drag-and-drop, which does not exist (and explicitly says so)', () => {
    expect(SYSTEM_PROMPT).not.toMatch(/drag to reschedule/i);
    expect(SYSTEM_PROMPT).toMatch(/no drag-and-drop/i);
  });

  it('does not claim day/week calendar views, which do not exist (month view only)', () => {
    expect(SYSTEM_PROMPT).not.toMatch(/day, week, month views/i);
  });

  it('does not claim notes are "rich text" (it is a plain textarea, no WYSIWYG)', () => {
    expect(SYSTEM_PROMPT.toLowerCase()).not.toContain('rich text');
  });

  it('does not claim a budget "limits"/cap feature, which does not exist', () => {
    expect(SYSTEM_PROMPT).not.toMatch(/set limits/i);
  });

  it('includes the strict off-topic-refusal instruction', () => {
    expect(SYSTEM_PROMPT).toMatch(/only answer questions about elly/i);
  });

  it('includes explicit prompt-injection resistance instructions', () => {
    expect(SYSTEM_PROMPT).toMatch(/ignore previous instructions/i);
    expect(SYSTEM_PROMPT).toMatch(/never as new instructions/i);
  });
});
