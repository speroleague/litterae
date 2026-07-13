<script lang="ts">
	import { ShieldCheckIcon } from 'phosphor-svelte';
	import { adminLogin } from '$lib/adminSession.svelte';

	let username = $state('');
	let password = $state('');
	let loading = $state(false);
	let error = $state<string | null>(null);

	async function handleSubmit(e: SubmitEvent) {
		e.preventDefault();
		error = null;
		loading = true;
		try {
			await adminLogin(username.trim(), password);
		} catch {
			error = 'Wrong username or password.';
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
			<ShieldCheckIcon size={26} weight="regular" />
		</div>
		<h1 class="mb-1 text-2xl font-semibold" style="color: var(--text);">litterae admin</h1>
		<p class="mb-8 text-sm" style="color: var(--text-muted);">Sign in to manage domains, accounts, and delivery.</p>

		<form onsubmit={handleSubmit} class="flex flex-col gap-3 text-left">
			<input
				type="text"
				placeholder="Username"
				bind:value={username}
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
				{loading ? 'Signing in…' : 'Sign in'}
			</button>
		</form>
	</div>
</div>
