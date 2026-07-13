// Persisted (localStorage, not sessionStorage -- a theme choice should
// survive across sessions/tabs, unlike the mail/admin auth tokens) light /
// dark / system theme. "system" means no override: layout.css's
// `prefers-color-scheme` media query decides. light/dark stamp
// `data-theme` on <html>, which layout.css's `:root[data-theme=...]`
// selectors win over the media query for.

export type ThemeMode = 'system' | 'light' | 'dark';

const STORAGE_KEY = 'litterae-theme';
const ORDER: ThemeMode[] = ['system', 'light', 'dark'];

class ThemeState {
	mode = $state<ThemeMode>('system');
}

export const themeState = new ThemeState();

function apply(mode: ThemeMode) {
	if (typeof document === 'undefined') return;
	if (mode === 'system') {
		delete document.documentElement.dataset.theme;
	} else {
		document.documentElement.dataset.theme = mode;
	}
}

if (typeof localStorage !== 'undefined') {
	const saved = localStorage.getItem(STORAGE_KEY);
	if (saved === 'light' || saved === 'dark' || saved === 'system') {
		themeState.mode = saved;
	}
	apply(themeState.mode);
}

export function setThemeMode(mode: ThemeMode) {
	themeState.mode = mode;
	apply(mode);
	if (typeof localStorage !== 'undefined') {
		localStorage.setItem(STORAGE_KEY, mode);
	}
}

export function cycleTheme() {
	const next = ORDER[(ORDER.indexOf(themeState.mode) + 1) % ORDER.length];
	setThemeMode(next);
}
