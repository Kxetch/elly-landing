import { describe, expect, it } from 'vitest';
import { isSafeLinkUrl, renderMarkdown } from './markdown';

const BASE = 'https://elly.example/';

describe('isSafeLinkUrl', () => {
  it('allows http and https', () => {
    expect(isSafeLinkUrl('https://github.com/Kxetch/elly-server', BASE)).toBe(true);
    expect(isSafeLinkUrl('http://example.com', BASE)).toBe(true);
  });

  it('allows mailto', () => {
    expect(isSafeLinkUrl('mailto:hello@example.com', BASE)).toBe(true);
  });

  it(
    'regression: rejects javascript: URIs -- the concrete XSS vector this ' +
      'allowlist exists to close. The chat reply is LLM-generated; a ' +
      'successful prompt-injection attempt could in principle coax the ' +
      'model into echoing a markdown link with an attacker-supplied href, ' +
      'which the caller renders via innerHTML.',
    () => {
      expect(isSafeLinkUrl('javascript:alert(1)', BASE)).toBe(false);
      expect(isSafeLinkUrl('JaVaScRiPt:alert(1)', BASE)).toBe(false);
    },
  );

  it('rejects data: URIs (another classic innerHTML XSS vector)', () => {
    expect(isSafeLinkUrl('data:text/html,<script>alert(1)</script>', BASE)).toBe(false);
  });

  it('rejects file: and other unexpected schemes', () => {
    expect(isSafeLinkUrl('file:///etc/passwd', BASE)).toBe(false);
    expect(isSafeLinkUrl('ftp://example.com', BASE)).toBe(false);
  });

  it('never throws, even for input that fails to resolve as a URL at all', () => {
    expect(() => isSafeLinkUrl('', BASE)).not.toThrow();
    expect(() => isSafeLinkUrl('http://', BASE)).not.toThrow();
  });
});

describe('renderMarkdown', () => {
  it('renders a safe link as a real, clickable anchor', () => {
    const out = renderMarkdown('See [the docs](https://example.com/docs) for more.', BASE);
    expect(out).toContain('<a href="https://example.com/docs" target="_blank" rel="noopener">the docs</a>');
  });

  it('renders an unsafe link as plain text, not a clickable anchor -- never silently dropped', () => {
    const out = renderMarkdown('Click [here](javascript:alert(1)) now.', BASE);
    expect(out).not.toContain('<a ');
    expect(out).not.toContain('javascript:');
    expect(out).toContain('here');
  });

  it('escapes raw HTML in the model reply before applying markdown, so an injected <script> tag never survives as an element', () => {
    const out = renderMarkdown('<script>alert(1)</script>', BASE);
    expect(out).not.toContain('<script>');
    expect(out).toContain('&lt;script&gt;');
  });

  it('renders bold/italic/inline code', () => {
    expect(renderMarkdown('**bold**', BASE)).toContain('<strong>bold</strong>');
    expect(renderMarkdown('*italic*', BASE)).toContain('<em>italic</em>');
    expect(renderMarkdown('`code`', BASE)).toContain('<code>code</code>');
  });

  it('renders a simple unordered list', () => {
    const out = renderMarkdown('- one\n- two', BASE);
    expect(out).toContain('<ul>');
    expect(out).toContain('<li>one</li>');
    expect(out).toContain('<li>two</li>');
  });

  it('wraps plain sentences in a paragraph', () => {
    expect(renderMarkdown('Hello there.', BASE)).toBe('<p>Hello there.</p>');
  });
});
