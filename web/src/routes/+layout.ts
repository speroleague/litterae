// Every route fetches its data client-side after mount; nothing here is
// prerenderable (message IDs in particular aren't known at build time).
// adapter-static's `fallback` handles serving index.html for these and
// letting client-side routing take over.
export const prerender = false;
export const ssr = false;
