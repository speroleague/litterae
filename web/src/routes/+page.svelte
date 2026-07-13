<script lang="ts">
	import { goto } from '$app/navigation';
	import { LockIcon } from 'phosphor-svelte';
	import { session, unlock } from '$lib/session.svelte';

	let email = $state('');
	let password = $state('');
	let loading = $state(false);
	let error = $state<string | null>(null);

	if (session.isUnlocked) {
		goto('/mail');
	}

	async function handleSubmit(e: SubmitEvent) {
		e.preventDefault();
		error = null;
		const at = email.lastIndexOf('@');
		if (at <= 0 || at === email.length - 1) {
			error = 'Enter a full email address.';
			return;
		}
		const localPart = email.slice(0, at).trim();
		const domain = email.slice(at + 1).trim();
		loading = true;
		try {
			await unlock(localPart, domain, password);
			await goto('/mail');
		} catch {
			error = 'Wrong address or password.';
		} finally {
			loading = false;
		}
	}
</script>

<div class="flex min-h-screen items-center justify-center px-6">
	<div class="w-full max-w-sm text-center">
		<div
			class="mx-auto mb-6 flex h-14 w-14 items-center justify-center rounded-full"
			style="background: var(--accent-weak); color: var(--accent);"
		>
			<LockIcon size={26} weight="regular" />
		</div>
		<h1 class="mb-1 text-2xl font-semibold" style="color: var(--text);">litterae</h1>
		<p class="mb-8 text-sm" style="color: var(--text-muted);">Enter your address and password to unlock your mailbox.</p>

		<form onsubmit={handleSubmit} class="flex flex-col gap-3 text-left">
			<input
				type="email"
				placeholder="alice@example.com"
				bind:value={email}
				required
				autocomplete="username"
				class="rounded-[var(--radius-sm)] border px-3 py-2.5 text-[15px] outline-none"
				style="background: var(--surface-sunk); border-color: var(--border); color: var(--text);"
			/>
			<input
				type="password"
				placeholder="Password"
				bind:value={password}
				required
				autocomplete="current-password"
				class="rounded-[var(--radius-sm)] border px-3 py-2.5 text-[15px] outline-none"
				style="background: var(--surface-sunk); border-color: var(--border); color: var(--text);"
			/>

			{#if error}
				<p class="text-sm" style="color: var(--danger);">{error}</p>
			{/if}

			<button
				type="submit"
				disabled={loading}
				class="mt-2 rounded-[var(--radius-sm)] py-2.5 text-[15px] font-medium text-white transition-opacity disabled:opacity-60"
				style="background: var(--accent);"
			>
				{loading ? 'Unlocking…' : 'Unlock'}
			</button>
		</form>
	</div>
</div>
