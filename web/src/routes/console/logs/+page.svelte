<script lang="ts">
	import { fade } from 'svelte/transition';
	import { FileTextIcon, ArrowClockwiseIcon, CaretDownIcon } from 'phosphor-svelte';
	import { adminSession } from '$lib/adminSession.svelte';
	import { getLogs, type LogEntry } from '$lib/admin';

	const WINDOWS = [
		{ label: '1h', secs: 60 * 60 },
		{ label: '6h', secs: 6 * 60 * 60 },
		{ label: '24h', secs: 24 * 60 * 60 },
		{ label: '7d', secs: 7 * 24 * 60 * 60 }
	];
	const LEVELS = ['ALL', 'ERROR', 'WARN', 'INFO', 'DEBUG'];

	let windowSecs = $state(WINDOWS[2].secs);
	let level = $state('ALL');
	let logs = $state<LogEntry[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);

	async function refresh() {
		const token = adminSession.token;
		if (!token) return;
		loading = true;
		try {
			const now = Math.floor(Date.now() / 1000);
			logs = await getLogs(token, {
				since: now - windowSecs,
				until: now,
				level: level === 'ALL' ? undefined : level
			});
			error = null;
		} catch {
			error = 'Could not load logs.';
		} finally {
			loading = false;
		}
	}

	$effect(() => {
		void windowSecs;
		void level;
		refresh();
	});

	function levelColor(lvl: string): string {
		switch (lvl.toUpperCase()) {
			case 'ERROR':
				return 'var(--danger)';
			case 'WARN':
				return '#b45309';
			default:
				return 'var(--text-faint)';
		}
	}
</script>

<div class="flex flex-col gap-6">
	<div class="flex items-center justify-between">
		<div>
			<h2 class="mb-1 text-base font-semibold" style="color: var(--text);">Logs</h2>
			<p class="text-sm" style="color: var(--text-muted);">Recent server log lines.</p>
		</div>
		<button
			onclick={refresh}
			aria-label="Refresh"
			class="flex h-11 w-11 items-center justify-center rounded-full text-[var(--text-muted)] transition-colors hover:bg-[var(--surface-hover)]"
		>
			<ArrowClockwiseIcon size={18} class={loading ? 'animate-spin' : ''} />
		</button>
	</div>

	<div class="flex flex-wrap items-center gap-3">
		<div class="flex gap-1 rounded-full p-1" style="background: var(--surface-sunk);">
			{#each WINDOWS as w (w.secs)}
				<button
					onclick={() => (windowSecs = w.secs)}
					class="rounded-full px-3 py-1.5 text-[13px] font-medium transition-colors"
					style={windowSecs === w.secs
						? 'background: var(--accent); color: white;'
						: 'color: var(--text-muted);'}
				>
					{w.label}
				</button>
			{/each}
		</div>
		<div class="relative">
			<select
				bind:value={level}
				class="appearance-none rounded-[var(--radius-sm)] border py-1.5 pr-8 pl-2.5 text-[13px] outline-none"
				style="background: var(--surface-sunk); border-color: var(--border); color: var(--text);"
			>
				{#each LEVELS as lvl (lvl)}
					<option value={lvl}>{lvl}</option>
				{/each}
			</select>
			<CaretDownIcon
				size={12}
				class="pointer-events-none absolute top-1/2 right-2.5 -translate-y-1/2"
				style="color: var(--text-faint);"
			/>
		</div>
	</div>

	{#if loading && logs.length === 0}
		<div class="flex animate-pulse flex-col gap-2">
			{#each Array(6) as _}
				<div class="h-10 rounded-[var(--radius-sm)]" style="background: var(--surface-sunk);"></div>
			{/each}
		</div>
	{:else if error}
		<p class="text-sm" style="color: var(--danger);">{error}</p>
	{:else if logs.length === 0}
		<div class="flex flex-col items-center gap-4 py-16 text-center" in:fade={{ duration: 200 }}>
			<div class="flex h-16 w-16 items-center justify-center rounded-full" style="background: var(--surface-sunk);">
				<FileTextIcon size={28} style="color: var(--text-faint);" />
			</div>
			<p class="text-sm" style="color: var(--text-faint);">No log entries in this range.</p>
		</div>
	{:else}
		<div class="overflow-x-auto rounded-[var(--radius)]" style="border: 1px solid var(--border);">
			<ul class="flex flex-col divide-y" style="border-color: var(--border);">
				{#each logs as entry, i (i)}
					<li class="flex flex-col gap-1 px-3.5 py-2.5" style="background: var(--surface);">
						<div class="flex items-center gap-2">
							<span class="shrink-0 text-xs font-mono" style="color: var(--text-faint);">
								{new Date(entry.timestamp).toLocaleString()}
							</span>
							<span
								class="shrink-0 rounded px-1.5 py-0.5 text-[10px] font-semibold tracking-wide"
								style={`color: ${levelColor(entry.level)}; background: color-mix(in oklch, ${levelColor(entry.level)} 15%, transparent);`}
							>
								{entry.level}
							</span>
							<span class="truncate text-xs" style="color: var(--text-faint);">{entry.target}</span>
						</div>
						<p class="text-[13px]" style="color: var(--text);">{entry.fields?.message ?? ''}</p>
					</li>
				{/each}
			</ul>
		</div>
	{/if}
</div>
