<script lang="ts">
	import { goto } from '$app/navigation';
	import { KeyIcon } from 'phosphor-svelte';
	import { adminMfaVerify } from '$lib/adminSession.svelte';

	let code = $state('');
	let loading = $state(false);
	let error = $state<string | null>(null);

	async function handleSubmit(e: SubmitEvent) {
		e.preventDefault();
		error = null;
		loading = true;
		try {
			await adminMfaVerify(code.trim());
			await goto('/console/domains');
		} catch {
			error = 'Wrong code. If you lost your device, enter one of your recovery codes instead.';
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
			<KeyIcon size={26} weight="regular" />
		</div>
		<h1 class="mb-1 text-2xl font-semibold" style="color: var(--text);">Two-factor authentication</h1>
		<p class="mb-8 text-sm" style="color: var(--text-muted);">
			Enter the 6-digit code from your authenticator app, or a recovery code.
		</p>

		<form onsubmit={handleSubmit} class="flex flex-col gap-3 text-left">
			<input
				type="text"
				inputmode="numeric"
				placeholder="Code"
				bind:value={code}
				required
				autocomplete="one-time-code"
				class="rounded-[var(--radius-sm)] border px-3 py-2.5 text-center text-[15px] tracking-widest outline-none"
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
				{loading ? 'Verifying…' : 'Verify'}
			</button>
		</form>
	</div>
</div>
