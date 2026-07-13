<script lang="ts">
	import { goto } from '$app/navigation';
	import { LockKeyIcon } from 'phosphor-svelte';
	import { adminSession, adminChangePassword } from '$lib/adminSession.svelte';

	let currentPassword = $state('');
	let newPassword = $state('');
	let confirmPassword = $state('');
	let loading = $state(false);
	let error = $state<string | null>(null);

	const forced = $derived(adminSession.mustChangePassword);

	async function handleSubmit(e: SubmitEvent) {
		e.preventDefault();
		error = null;
		if (newPassword !== confirmPassword) {
			error = "New passwords don't match.";
			return;
		}
		if (newPassword.length < 8) {
			error = 'New password must be at least 8 characters.';
			return;
		}
		loading = true;
		try {
			await adminChangePassword(currentPassword, newPassword);
			await goto('/console/domains');
		} catch {
			error = 'Current password is incorrect.';
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
			<LockKeyIcon size={26} weight="regular" />
		</div>
		<h1 class="mb-1 text-2xl font-semibold" style="color: var(--text);">
			{forced ? 'Set a new password' : 'Change password'}
		</h1>
		<p class="mb-8 text-sm" style="color: var(--text-muted);">
			{forced
				? 'This is your first login with the bootstrap password -- pick a permanent one before continuing.'
				: 'Update your admin password.'}
		</p>

		<form onsubmit={handleSubmit} class="flex flex-col gap-3 text-left">
			<input
				type="password"
				placeholder="Current password"
				bind:value={currentPassword}
				required
				autocomplete="current-password"
				class="rounded-[var(--radius-sm)] border px-3 py-2.5 text-[15px] outline-none"
				style="background: var(--surface-sunk); border-color: var(--border); color: var(--text);"
			/>
			<input
				type="password"
				placeholder="New password"
				bind:value={newPassword}
				required
				autocomplete="new-password"
				class="rounded-[var(--radius-sm)] border px-3 py-2.5 text-[15px] outline-none"
				style="background: var(--surface-sunk); border-color: var(--border); color: var(--text);"
			/>
			<input
				type="password"
				placeholder="Confirm new password"
				bind:value={confirmPassword}
				required
				autocomplete="new-password"
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
				{loading ? 'Saving…' : 'Save password'}
			</button>
		</form>
	</div>
</div>
