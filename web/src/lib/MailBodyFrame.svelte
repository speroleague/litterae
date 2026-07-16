<script lang="ts">
	import { ImageIcon } from 'phosphor-svelte';
	import { buildSrcdoc } from './mailBodyFrame';
	import { themeState } from './theme.svelte';
	import LinkConfirmDialog from './LinkConfirmDialog.svelte';

	let { bodyHtml, blockedImageCount }: { bodyHtml: string; blockedImageCount: number } = $props();

	let iframeEl: HTMLIFrameElement | undefined = $state();
	let height = $state(80);
	let imagesRevealed = $state(false);
	let linkDialogOpen = $state(false);
	let pendingHref = $state<string | null>(null);

	let srcdoc = $derived(buildSrcdoc(bodyHtml, themeState.mode));

	// No `allow-same-origin` -- the iframe gets an opaque origin with no
	// reachable cookies/storage, and this listener is the only bridge back
	// out, gated on `event.source` (an opaque-origin frame's `event.origin`
	// is just the string "null", useless as a check).
	$effect(() => {
		function onMessage(e: MessageEvent) {
			if (!iframeEl || e.source !== iframeEl.contentWindow) return;
			const data = e.data;
			if (data?.type === 'litterae:resize' && typeof data.height === 'number') {
				height = Math.max(40, Math.ceil(data.height));
			} else if (data?.type === 'litterae:link-click' && typeof data.href === 'string') {
				pendingHref = data.href;
				linkDialogOpen = true;
			}
		}
		window.addEventListener('message', onMessage);
		return () => window.removeEventListener('message', onMessage);
	});

	function revealImages() {
		iframeEl?.contentWindow?.postMessage({ type: 'litterae:reveal-images' }, '*');
		imagesRevealed = true;
	}
</script>

{#if blockedImageCount > 0 && !imagesRevealed}
	<button
		onclick={revealImages}
		class="mb-3 flex items-center gap-1.5 rounded-full px-3 py-1.5 text-xs font-medium transition-colors hover:bg-[var(--surface-hover)]"
		style="background: var(--surface-sunk); color: var(--text-muted); border: 1px solid var(--border);"
	>
		<ImageIcon size={14} />
		{blockedImageCount} tracker{blockedImageCount === 1 ? '' : 's'} blocked · Load images
	</button>
{/if}

<iframe
	bind:this={iframeEl}
	title="Message content"
	sandbox="allow-scripts"
	{srcdoc}
	class="rounded-[var(--radius)]"
	style="width: 100%; height: {height}px; display: block; max-width: 90ch; border: 1px solid var(--border); background: var(--surface);"
></iframe>

<LinkConfirmDialog bind:open={linkDialogOpen} href={pendingHref} />
