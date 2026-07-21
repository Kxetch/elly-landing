import type { APIRoute } from 'astro';
import {
  SYSTEM_PROMPT,
  checkDistributedRateLimits,
  checkSoftHourlyQuota,
  getClientIp,
  isLongEnough,
  isValidMessageField,
  sanitizeInput,
  type ChatRateLimitBindings,
} from '../../lib/chatSafety';

// Best-effort UX hint only ("N questions remaining this hour") -- the
// real security boundary is the Cloudflare rate-limiting bindings
// checked below. See chatSafety.ts's own comments for why a plain
// module-level Map like this one cannot be relied on for actual
// enforcement on Workers.
const softQuotaStore = new Map<string, { count: number; resetTime: number }>();

function jsonResponse(body: unknown, status: number, extraHeaders?: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
  });
}

export const POST: APIRoute = async ({ request }) => {
  let env: Partial<Env> = {};
  try {
    const cf = await import('cloudflare:workers');
    env = cf.env as Partial<Env>;
  } catch {
    env = {};
  }

  const clientIp = getClientIp(request);

  // The real, hard defense: distributed, non-spoofable, checked
  // before anything else runs (no body parsing, no OpenAI call) so a
  // blocked request costs as close to nothing as possible.
  if (env.CHAT_RATE_LIMITER && env.CHAT_GLOBAL_RATE_LIMITER) {
    const bindings: ChatRateLimitBindings = {
      perVisitor: env.CHAT_RATE_LIMITER,
      global: env.CHAT_GLOBAL_RATE_LIMITER,
    };
    const result = await checkDistributedRateLimits(bindings, clientIp);
    if (!result.allowed) {
      // Deliberately the same generic message regardless of which
      // layer (per-visitor vs sitewide) rejected it -- doesn't give
      // an attacker a signal to tune requests around.
      return jsonResponse(
        { error: 'Rate limit exceeded. Please try again in a minute.', resetIn: 1 },
        429,
      );
    }
  } else {
    // No rate-limit bindings available at all -- only expected when
    // running plain `astro dev` without the Cloudflare dev runtime.
    // Never silently skip this in anything that could be a real
    // deployment; fail loudly instead of failing open.
    console.warn('Chat rate-limit bindings unavailable -- refusing to serve without them.');
    return jsonResponse({ error: 'AI service not configured' }, 503);
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: 'Invalid request body' }, 400);
  }

  const message = (body as { message?: unknown } | null)?.message;

  if (!isValidMessageField(message)) {
    return jsonResponse({ error: 'Message is required' }, 400);
  }

  const sanitized = sanitizeInput(message);

  if (!isLongEnough(sanitized)) {
    return jsonResponse({ error: 'Message too short' }, 400);
  }

  const apiKey = env.OPENAI_API_KEY;
  if (!apiKey) {
    return jsonResponse({ error: 'AI service not configured' }, 503);
  }

  const { remaining } = checkSoftHourlyQuota(softQuotaStore, clientIp);

  try {
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: 'gpt-4o-mini',
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user', content: sanitized },
        ],
        max_tokens: 200,
        // Low temperature: this is a factual support bot, not a
        // creative one -- accuracy and consistency matter far more
        // than variety in the phrasing of, say, the pricing answer.
        temperature: 0.2,
        presence_penalty: 0,
        // A small frequency penalty discourages repeating whole
        // sentences verbatim without discouraging the model from
        // saying "elly" as often as it naturally would -- the
        // previous 0.3 was high enough to occasionally do the latter.
        frequency_penalty: 0.1,
      }),
    });

    if (!response.ok) {
      const errorData = await response.text();
      console.error('OpenAI API error:', response.status, errorData);
      return jsonResponse({ error: 'AI service temporarily unavailable' }, 502);
    }

    const data = (await response.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
    };
    const reply = data.choices?.[0]?.message?.content;

    if (!reply) {
      return jsonResponse({ error: 'No response from AI' }, 502);
    }

    return jsonResponse({ reply: reply.trim(), remaining }, 200);
  } catch (error) {
    console.error('Chat error:', error);
    return jsonResponse({ error: 'Something went wrong' }, 500);
  }
};

export const prerender = false;
