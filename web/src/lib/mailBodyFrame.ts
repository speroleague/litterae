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

/**
 * Assembles the iframe's `srcdoc` from an already-sanitized HTML fragment.
 * `sanitizedBodyHtml` must come from the server's `html_sanitize` output --
 * this function does no sanitization itself, it only wraps trusted
 * structure around opaque, already-safe content.
 */
export function buildSrcdoc(sanitizedBodyHtml: string): string {
	return `<!doctype html><html><head><meta charset="utf-8"></head><body>${sanitizedBodyHtml}<script>${TRUSTED_SCRIPT}</script></body></html>`;
}
