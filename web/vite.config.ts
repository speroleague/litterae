import tailwindcss from '@tailwindcss/vite';
import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

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
			adapter: adapter({ fallback: 'index.html' })
		})
	]
});
