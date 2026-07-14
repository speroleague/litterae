import { createHash } from 'node:crypto';
import tailwindcss from '@tailwindcss/vite';
import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';
import { TRUSTED_SCRIPT } from './src/lib/mailBodyFrame';

// The message-body iframe (MailBodyFrame.svelte) is a `srcdoc` document,
// which inherits this page's CSP -- so the one script that ever runs in
// it needs its hash allowed here too. Computed from the actual constant
// rather than hand-copied so it can't silently drift out of sync.
const trustedScriptHash: `sha256-${string}` = `sha256-${createHash('sha256').update(TRUSTED_SCRIPT).digest('base64')}`;

export default defineConfig({
	plugins: [
		tailwindcss(),
		sveltekit({
			compilerOptions: {
				// Force runes mode for the project, except for libraries. Can be removed in svelte 6.
				runes: ({ filename }) => filename.split(/[/\\]/).includes('node_modules') ? undefined : true
			},

			// Every route fetches its data client-side after mount (no server
			// load functions anywhere), so this is a pure static SPA -- Caddy
			// serves the built files directly, no Node runtime needed.
			// `fallback` lets client-side routing handle /mail/[id] (message
			// IDs aren't known at build time, so they can't be prerendered).
			adapter: adapter({ fallback: 'index.html' }),

			// Hashes the inline hydration bootstrap script automatically
			// (its hash changes every build). frame-ancestors/report-uri/
			// sandbox can't go through <meta>, so those stay in Caddyfile.
			csp: {
				mode: 'hash',
				directives: {
					'default-src': ['self'],
					'connect-src': ['self'],
					'img-src': ['self', 'data:'],
					'style-src': ['self', 'unsafe-inline'],
					'script-src': ['self', trustedScriptHash],
					'base-uri': ['none'],
					'form-action': ['self']
				}
			}
		})
	]
});
