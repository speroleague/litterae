// The only script that ever runs inside a message-body iframe (see
// MailBodyFrame.svelte) -- everything else in the sanitized HTML is inert
// markup by construction (see crates/jmap/src/html_sanitize.rs). Kept as a
// literal, never templated with message or server data, so its CSP hash
// (computed from this exact string in vite.config.ts) is the only script
// that can ever execute in that document.
export const TRUSTED_SCRIPT = `document.addEventListener('click', function (e) {
	var a = e.target.closest('a[data-real-href]');
	if (!a) return;
	e.preventDefault();
	parent.postMessage({ type: 'litterae:link-click', href: a.getAttribute('data-real-href') }, '*');
}, true);

window.addEventListener('message', function (e) {
	if (!e.data || e.data.type !== 'litterae:reveal-images') return;
	document.querySelectorAll('img[data-blocked-src]').forEach(function (img) {
		img.src = img.getAttribute('data-blocked-src');
		img.removeAttribute('data-blocked-src');
	});
});

function reportHeight() {
	parent.postMessage({ type: 'litterae:resize', height: document.documentElement.scrollHeight }, '*');
}
new ResizeObserver(reportHeight).observe(document.documentElement);
reportHeight();
`;

// Mirrors layout.css's --surface/--text tokens (light and dark). A srcdoc
// document is its own browsing context -- it doesn't inherit the parent
// page's CSS custom properties, so without this the iframe falls back to
// the browser default (white/black) no matter what theme the rest of the
// app is in. `prefers-color-scheme` still works here on its own (it's an
// OS-level media feature, not something that needs to cross the frame
// boundary); only an explicit light/dark override needs to be threaded in
// from the parent, since `data-theme` on the parent's <html> obviously
// isn't visible inside this separate document.
const THEME_STYLE = `:root {
	color-scheme: light;
	background: oklch(0.995 0.004 95);
	color: oklch(0.32 0.01 260);
}
@media (prefers-color-scheme: dark) {
	:root { color-scheme: dark; background: oklch(0.25 0.008 260); color: oklch(0.9 0.01 260); }
}
:root[data-theme='dark'] { color-scheme: dark; background: oklch(0.25 0.008 260); color: oklch(0.9 0.01 260); }
:root[data-theme='light'] { color-scheme: light; background: oklch(0.995 0.004 95); color: oklch(0.32 0.01 260); }
body { margin: 0; padding: 12px; background: inherit; color: inherit; }`;

/**
 * Assembles the iframe's `srcdoc` from an already-sanitized HTML fragment.
 * `sanitizedBodyHtml` must come from the server's `html_sanitize` output --
 * this function does no sanitization itself, it only wraps trusted
 * structure around opaque, already-safe content.
 *
 * `theme` is the app's current `ThemeMode` ('system' | 'light' | 'dark').
 * 'system' is left alone (the `prefers-color-scheme` rule above already
 * handles it); an explicit override is stamped onto this document's own
 * <html> the same way `theme.svelte.ts` stamps it on the parent's.
 */
export function buildSrcdoc(sanitizedBodyHtml: string, theme: 'system' | 'light' | 'dark'): string {
	const themeAttr = theme === 'system' ? '' : ` data-theme="${theme}"`;
	return `<!doctype html><html${themeAttr}><head><meta charset="utf-8"><style>${THEME_STYLE}</style></head><body>${sanitizedBodyHtml}<script>${TRUSTED_SCRIPT}</script></body></html>`;
}
