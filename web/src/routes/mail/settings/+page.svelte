<script lang="ts">
	import { goto } from '$app/navigation';
	import { CaretLeftIcon, CheckIcon } from 'phosphor-svelte';
	import { session } from '$lib/session.svelte';
	import { getIdentity, setIdentitySignature } from '$lib/jmap';
	import { setSignature } from '$lib/composeState.svelte';

	let identityId = $state<string | null>(null);
	let text = $state('');
	let loading = $state(true);
	let saving = $state(false);
	let saved = $state(false);
	let error = $state<string | null>(null);

	$effect(() => {
		const token = session.token;
		const accountId = session.accountId;
		if (!token || !accountId) return;
		getIdentity(token, accountId)
			.then((identity) => {
				identityId = identity?.id ?? null;
				text = identity?.textSignature ?? '';
				error = null;
			})
			.catch(() => {
				error = 'Could not load your signature.';
			})
			.finally(() => {
				loading = false;
			});
	});

	async function save() {
		const token = session.token;
		const accountId = session.accountId;
		if (!token || !accountId || !identityId || saving) return;
		saving = true;
		saved = false;
		error = null;
		try {
			await setIdentitySignature(token, accountId, identityId, text);
			setSignature(text);
			saved = true;
			setTimeout(() => (saved = false), 2000);
		} catch {
			error = 'Could not save your signature.';
		} finally {
			saving = false;
		}
	}
</script>

<div class="mx-auto flex min-h-screen max-w-2xl flex-col">
	<header
		class="flex items-center gap-2 px-2 py-3"
		style="border-bottom: 1px solid var(--border);"
	>
		<button
			onclick={() => goto('/mail')}
			aria-label="Back"
			class="flex h-11 w-11 items-center justify-center rounded-full transition-colors hover:bg-[var(--surface-hover)]"
			style="color: var(--text-muted);"
		>
			<CaretLeftIcon size={20} />
		</button>
		<h1 class="text-[15px] font-semibold" style="color: var(--text);">Signature</h1>
	</header>

	<main class="flex-1 px-5 py-5">
		{#if loading}
			<div class="h-32 animate-pulse rounded-[var(--radius)]" style="background: var(--surface-sunk);"></div>
		{:else}
			<p class="mb-3 text-sm" style="color: var(--text-faint);">
				Inserted into new messages and replies -- you can still edit or remove it per message.
			</p>
			<textarea
				bind:value={text}
				placeholder="Your name"
				rows="6"
				class="w-full resize-y rounded-[var(--radius)] p-3 text-[15px] leading-relaxed outline-none"
				style="background: var(--surface); border: 1px solid var(--border); color: var(--text); max-width: 60ch;"
			></textarea>

			{#if error}
				<p class="mt-2 text-sm" style="color: var(--danger);">{error}</p>
			{/if}

			<div class="mt-4 flex items-center gap-3">
				<button
					onclick={save}
					disabled={saving}
					class="rounded-[var(--radius-sm)] px-4 py-2 text-[14px] font-medium text-white transition-opacity disabled:opacity-60"
					style="background: var(--accent);"
				>
					{saving ? 'Saving…' : 'Save'}
				</button>
				{#if saved}
					<span class="flex items-center gap-1 text-sm" style="color: var(--text-faint);">
						<CheckIcon size={16} weight="bold" />
						Saved
					</span>
				{/if}
			</div>
		{/if}
	</main>
</div>
