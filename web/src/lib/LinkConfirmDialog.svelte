<script lang="ts">
	import { WarningCircleIcon } from 'phosphor-svelte';
	import Dialog from './Dialog.svelte';

	let { open = $bindable(false), href }: { open?: boolean; href: string | null } = $props();

	// Re-validated here, not just trusted from the iframe -- defense in
	// depth against a sanitizer regression upstream.
	function isSafeToOpen(url: string | null): boolean {
		if (!url) return false;
		try {
			return ['http:', 'https:', 'mailto:'].includes(new URL(url).protocol);
		} catch {
			return false;
		}
	}

	function proceed() {
		if (href && isSafeToOpen(href)) {
			window.open(href, '_blank', 'noopener,noreferrer');
		}
		open = false;
	}
</script>

<Dialog bind:open>
	<div class="flex items-start gap-3">
		<WarningCircleIcon size={22} weight="fill" style="color: var(--accent); flex-shrink: 0; margin-top: 2px;" />
		<div class="min-w-0">
			<h2 class="text-[15px] font-semibold" style="color: var(--text);">Leaving litterae</h2>
			<p class="mt-1 text-sm break-words" style="color: var(--text-muted);">
				This link goes to:
			</p>
			<p class="mt-1 rounded-[var(--radius-sm)] px-2.5 py-2 text-sm break-all" style="background: var(--surface-sunk); color: var(--text);">
				{href}
			</p>
		</div>
	</div>
	<div class="mt-4 flex justify-end gap-2">
		<button
			onclick={() => (open = false)}
			class="rounded-[var(--radius-sm)] px-3.5 py-2 text-[14px] font-medium transition-opacity hover:opacity-80"
			style="color: var(--text-muted); background: var(--surface-sunk);"
		>
			Cancel
		</button>
		<button
			onclick={proceed}
			disabled={!isSafeToOpen(href)}
			class="rounded-[var(--radius-sm)] px-3.5 py-2 text-[14px] font-medium text-white transition-opacity hover:opacity-90 disabled:opacity-50"
			style="background: var(--accent);"
		>
			Continue
		</button>
	</div>
</Dialog>
