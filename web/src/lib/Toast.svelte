<script lang="ts">
	import { fly, fade } from 'svelte/transition';
	import { XIcon, WarningCircleIcon, CheckCircleIcon } from 'phosphor-svelte';
	import { toastState, dismissToast } from './toast.svelte';
</script>

<div
	class="pointer-events-none fixed inset-x-0 bottom-0 z-50 flex flex-col items-center gap-2 px-4 pb-[calc(1rem+env(safe-area-inset-bottom))] sm:items-end sm:pr-6"
>
	{#each toastState.items as item (item.id)}
		<div
			class="pointer-events-auto flex w-full max-w-sm items-start gap-2.5 rounded-[var(--radius)] px-4 py-3 shadow-lg"
			style="background: var(--surface); border: 1px solid var(--border);"
			role="alert"
			in:fly={{ y: 16, duration: 180 }}
			out:fade={{ duration: 120 }}
		>
			{#if item.variant === 'error'}
				<WarningCircleIcon size={18} weight="fill" style="color: var(--danger); flex-shrink: 0; margin-top: 1px;" />
			{:else}
				<CheckCircleIcon size={18} weight="fill" style="color: var(--success); flex-shrink: 0; margin-top: 1px;" />
			{/if}
			<p class="flex-1 text-sm" style="color: var(--text);">{item.message}</p>
			<button
				onclick={() => dismissToast(item.id)}
				aria-label="Dismiss"
				class="shrink-0 rounded-full p-0.5"
				style="color: var(--text-faint);"
			>
				<XIcon size={16} />
			</button>
		</div>
	{/each}
</div>
