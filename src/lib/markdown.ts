/**
 * Lightweight markdown -> HTML rendering for the chat widget's bot
 * replies. Extracted from ChatWidget.astro's inline <script> so the
 * link-scheme allowlist (the actual security-relevant part) has real
 * unit test coverage -- an inline Astro script isn't an importable
 * module, so it couldn't be tested directly before.
 */

/**
 * Only these URL schemes are ever rendered as a clickable link. The
 * text being rendered here is LLM-generated (a chat reply) -- our
 * system prompt instructs the model to only discuss elly, but a
 * successful prompt-injection attempt could in principle coax it into
 * echoing back an attacker-supplied `javascript:`/`data:` URI in
 * markdown link syntax, which `innerHTML` (used by the caller) would
 * otherwise render as a real, clickable XSS vector. Anything not on
 * this allowlist renders as plain text instead of a link -- never
 * silently dropped, so a legitimate-looking but unsupported link is
 * still visible to read, just not clickable.
 *
 * `baseUrl` resolves a relative URL the same way a browser would;
 * pass `location.href` in the browser, or any absolute URL in tests.
 */
export function isSafeLinkUrl(url: string, baseUrl: string): boolean {
  try {
    const parsed = new URL(url, baseUrl);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' || parsed.protocol === 'mailto:';
  } catch {
    return false;
  }
}

export function renderMarkdown(text: string, baseUrl: string): string {
  const html = text
    // escape HTML
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    // bold **text** or __text__
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/__(.+?)__/g, '<strong>$1</strong>')
    // italic *text* or _text_
    .replace(/(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)/g, '<em>$1</em>')
    .replace(/(?<!_)_(?!_)(.+?)(?<!_)_(?!_)/g, '<em>$1</em>')
    // inline code `text`
    .replace(/`(.+?)`/g, '<code>$1</code>')
    // links [text](url) -- see isSafeLinkUrl above
    .replace(/\[(.+?)\]\((.+?)\)/g, (_match, label: string, url: string) =>
      isSafeLinkUrl(url, baseUrl)
        ? `<a href="${url}" target="_blank" rel="noopener">${label}</a>`
        : label,
    );

  // line breaks -> <br>, then handle lists
  const lines = html.split('\n');
  let result = '';
  let inList = false;

  for (const line of lines) {
    const trimmed = line.trim();
    // unordered list
    const ulMatch = trimmed.match(/^[-*+]\s+(.*)/);
    // ordered list
    const olMatch = trimmed.match(/^\d+\.\s+(.*)/);

    if (ulMatch) {
      if (!inList) { result += '<ul>'; inList = true; }
      result += `<li>${ulMatch[1]}</li>`;
    } else if (olMatch) {
      if (!inList) { result += '<ul>'; inList = true; }
      result += `<li>${olMatch[1]}</li>`;
    } else {
      if (inList) { result += '</ul>'; inList = false; }
      if (trimmed === '') {
        result += '<br>';
      } else {
        result += trimmed + ' ';
      }
    }
  }
  if (inList) result += '</ul>';

  // Clean up multiple breaks
  let cleaned = result.replace(/<br>\s*<br>/g, '<br>').trim();

  // Wrap in paragraph if no block elements
  if (!cleaned.includes('<ul>') && !cleaned.includes('<ol>')) {
    cleaned = `<p>${cleaned}</p>`;
  }

  return cleaned;
}
