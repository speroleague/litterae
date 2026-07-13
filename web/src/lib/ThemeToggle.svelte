<script lang="ts">
	import { SunIcon, MoonIcon, DesktopIcon } from 'phosphor-svelte';
	import { themeState, cycleTheme } from '$lib/theme.svelte';

	const LABELS: Record<string, string> = { system: 'System theme', light: 'Light theme', dark: 'Dark theme' };
</script>

<button
	onclick={cycleTheme}
	aria-label={`${LABELS[themeState.mode]} -- tap to change`}
	class="flex h-11 w-11 items-center justify-center rounded-full transition-colors hover:bg-[var(--surface-hover)]"
	style="color: var(--text-muted);"
>
	{#if themeState.mode === 'system'}
		<DesktopIcon size={19} />
	{:else if themeState.mode === 'light'}
		<SunIcon size={19} />
	{:else}
		<MoonIcon size={19} />
	{/if}
</button>
