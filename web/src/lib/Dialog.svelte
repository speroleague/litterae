<script lang="ts">
	import type { Snippet } from 'svelte';
	import { fade, fly } from 'svelte/transition';

	let { open = $bindable(false), onClose, children }: {
		open?: boolean;
		onClose?: () => void;
		children: Snippet;
	} = $props();

	function close() {
		open = false;
		onClose?.();
	}
</script>

{#if open}
	<div class="fixed inset-0 z-40 flex items-center justify-center p-4">
		<button
			aria-label="Close"
			class="fixed inset-0 cursor-default"
			style="background: rgba(0,0,0,0.4);"
			onclick={close}
			transition:fade={{ duration: 150 }}
		></button>
		<div
			class="relative z-10 w-full max-w-sm rounded-[var(--radius)] p-5"
			style="background: var(--surface); border: 1px solid var(--border);"
			transition:fly={{ y: 12, duration: 150 }}
		>
			{@render children()}
		</div>
	</div>
{/if}
