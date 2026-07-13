<script lang="ts">
	import { fade } from 'svelte/transition';
	import { StackIcon, ArrowClockwiseIcon } from 'phosphor-svelte';
	import { adminSession } from '$lib/adminSession.svelte';
	import { getQueueStatus, type QueueStatusResponse } from '$lib/admin';

	let status = $state<QueueStatusResponse | null>(null);
	let loading = $state(true);
	let error = $state<string | null>(null);

	const STATS: { key: keyof QueueStatusResponse['metrics']; label: string }[] = [
		{ key: 'ready', label: 'Ready' },
		{ key: 'claimed', label: 'Claimed' },
		{ key: 'deferred', label: 'Deferred' },
		{ key: 'delivered', label: 'Delivered' },
		{ key: 'failed', label: 'Failed' },
		{ key: 'expired', label: 'Expired' }
	];

	async function refresh() {
		const token = adminSession.token;
		if (!token) return;
		loading = true;
		try {
			status = await getQueueStatus(token);
			error = null;
		} catch {
			error = 'Could not load queue status.';
		} finally {
			loading = false;
		}
	}

	$effect(() => {
		refresh();
	});
</script>

<div class="flex flex-col gap-6">
	<div class="flex items-center justify-between">
		<div>
			<h2 class="mb-1 text-base font-semibold" style="color: var(--text);">Queue</h2>
			<p class="text-sm" style="color: var(--text-muted);">Outbound delivery status and recent failures.</p>
		</div>
		<button
			onclick={refresh}
			aria-label="Refresh"
			class="flex h-11 w-11 items-center justify-center rounded-full text-[var(--text-muted)] transition-colors hover:bg-[var(--surface-hover)]"
		>
			<ArrowClockwiseIcon size={18} class={loading ? 'animate-spin' : ''} />
		</button>
	</div>

	{#if loading && !status}
		<div class="grid animate-pulse grid-cols-2 gap-2 sm:grid-cols-3">
			{#each Array(6) as _}
				<div class="h-20 rounded-[var(--radius)]" style="background: var(--surface-sunk);"></div>
			{/each}
		</div>
	{:else if error}
		<p class="text-sm" style="color: var(--danger);">{error}</p>
	{:else if status}
		<div class="grid grid-cols-2 gap-2 sm:grid-cols-3">
			{#each STATS as stat (stat.key)}
				<div class="rounded-[var(--radius)] p-4" style="background: var(--surface); border: 1px solid var(--border);">
					<div class="text-2xl font-semibold" style="color: var(--text);">{status.metrics[stat.key]}</div>
					<div class="text-xs" style="color: var(--text-faint);">{stat.label}</div>
				</div>
			{/each}
		</div>

		<div>
			<h3 class="mb-2 text-sm font-medium" style="color: var(--text);">Recent failures</h3>
			{#if status.recentFailures.length === 0}
				<div class="flex flex-col items-center gap-4 py-12 text-center" in:fade={{ duration: 200 }}>
					<div class="flex h-14 w-14 items-center justify-center rounded-full" style="background: var(--surface-sunk);">
						<StackIcon size={24} style="color: var(--text-faint);" />
					</div>
					<p class="text-sm" style="color: var(--text-faint);">No recent failures.</p>
				</div>
			{:else}
				<ul class="flex flex-col gap-2">
					{#each status.recentFailures as failure (failure.id)}
						<li class="rounded-[var(--radius)] p-3.5" style="background: var(--surface); border: 1px solid var(--border);">
							<div class="flex items-center justify-between gap-2">
								<span class="truncate text-[14px] font-medium" style="color: var(--text);">{failure.rcptTo}</span>
								{#if failure.lastCode}
									<span
										class="shrink-0 rounded-full px-2 py-0.5 text-xs font-medium"
										style="background: var(--danger); color: white;"
									>
										{failure.lastCode}
									</span>
								{/if}
							</div>
							<div class="mt-1 text-xs" style="color: var(--text-faint);">
								{failure.domain} &middot; {failure.attempts} attempt{failure.attempts === 1 ? '' : 's'}
							</div>
							{#if failure.lastStatus || failure.lastDetail}
								<div class="mt-1.5 text-xs" style="color: var(--text-muted);">
									{failure.lastStatus ?? ''} {failure.lastDetail ?? ''}
								</div>
							{/if}
						</li>
					{/each}
				</ul>
			{/if}
		</div>
	{/if}
</div>
