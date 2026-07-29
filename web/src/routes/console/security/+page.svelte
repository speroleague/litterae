<script lang="ts">
	import { ShieldCheckIcon, LockKeyIcon, CopyIcon } from 'phosphor-svelte';
	import { adminSession, adminMfaEnroll, adminMfaConfirm, adminMfaDisable } from '$lib/adminSession.svelte';

	type View = 'status' | 'enrolling' | 'recovery-codes' | 'disabling';

	let view = $state<View>('status');
	let secret = $state('');
	let otpauthUrl = $state('');
	let code = $state('');
	let disablePassword = $state('');
	let recoveryCodes = $state<string[]>([]);
	let loading = $state(false);
	let error = $state<string | null>(null);

	async function startEnroll() {
		error = null;
		loading = true;
		try {
			const result = await adminMfaEnroll();
			secret = result.secret;
			otpauthUrl = result.otpauthUrl;
			code = '';
			view = 'enrolling';
		} catch {
			error = 'Could not start enrollment. Refresh and try again.';
		} finally {
			loading = false;
		}
	}

	async function confirmEnroll(e: SubmitEvent) {
		e.preventDefault();
		error = null;
		loading = true;
		try {
			recoveryCodes = await adminMfaConfirm(code.trim());
			view = 'recovery-codes';
		} catch {
			error = 'Wrong code -- check your authenticator app and try again.';
		} finally {
			loading = false;
		}
	}

	async function confirmDisable(e: SubmitEvent) {
		e.preventDefault();
		error = null;
		loading = true;
		try {
			await adminMfaDisable(disablePassword);
			disablePassword = '';
			view = 'status';
		} catch {
			error = 'Wrong password.';
		} finally {
			loading = false;
		}
	}

	function doneWithRecoveryCodes() {
		recoveryCodes = [];
		view = 'status';
	}
</script>

<div class="mx-auto max-w-lg">
	<h1 class="mb-1 text-xl font-semibold" style="color: var(--text);">Security</h1>
	<p class="mb-6 text-sm" style="color: var(--text-muted);">Signed in as {adminSession.username}.</p>

	<section
		class="mb-6 rounded-[var(--radius-md)] border p-5"
		style="background: var(--surface); border-color: var(--border);"
	>
		<div class="mb-1 flex items-center gap-2">
			<LockKeyIcon size={18} style="color: var(--text-muted);" />
			<h2 class="text-[15px] font-medium" style="color: var(--text);">Password</h2>
		</div>
		<p class="mb-3 text-sm" style="color: var(--text-muted);">Change your admin password.</p>
		<a
			href="/console/change-password"
			class="inline-block rounded-[var(--radius-sm)] border px-3 py-2 text-sm font-medium"
			style="border-color: var(--border); color: var(--text);"
		>
			Change password
		</a>
	</section>

	<section
		class="rounded-[var(--radius-md)] border p-5"
		style="background: var(--surface); border-color: var(--border);"
	>
		<div class="mb-1 flex items-center gap-2">
			<ShieldCheckIcon size={18} style="color: var(--text-muted);" />
			<h2 class="text-[15px] font-medium" style="color: var(--text);">Two-factor authentication</h2>
		</div>

		{#if view === 'status'}
			<p class="mb-3 text-sm" style="color: var(--text-muted);">
				{adminSession.totpEnabled
					? 'Enabled -- an authenticator code is required at login.'
					: 'Not enabled. Add an authenticator app for a second login factor.'}
			</p>
			{#if error}
				<p class="mb-3 text-sm" style="color: var(--danger);">{error}</p>
			{/if}
			{#if adminSession.totpEnabled}
				<button
					onclick={() => (view = 'disabling')}
					class="rounded-[var(--radius-sm)] border px-3 py-2 text-sm font-medium"
					style="border-color: var(--danger); color: var(--danger);"
				>
					Disable
				</button>
			{:else}
				<button
					onclick={startEnroll}
					disabled={loading}
					class="rounded-[var(--radius-sm)] px-3 py-2 text-sm font-medium text-white disabled:opacity-60"
					style="background: var(--accent);"
				>
					{loading ? 'Starting…' : 'Enable two-factor authentication'}
				</button>
			{/if}
		{:else if view === 'enrolling'}
			<p class="mb-3 text-sm" style="color: var(--text-muted);">
				Scan this into your authenticator app, or enter the key manually, then confirm with a code.
			</p>
			<div
				class="mb-3 flex items-center justify-between gap-2 rounded-[var(--radius-sm)] border px-3 py-2"
				style="background: var(--surface-sunk); border-color: var(--border);"
			>
				<code class="truncate text-sm" style="color: var(--text);">{secret}</code>
				<button
					aria-label="Copy secret"
					onclick={() => navigator.clipboard.writeText(secret)}
					class="shrink-0"
					style="color: var(--text-muted);"
				>
					<CopyIcon size={16} />
				</button>
			</div>
			<form onsubmit={confirmEnroll} class="flex flex-col gap-3">
				<input
					type="text"
					inputmode="numeric"
					placeholder="6-digit code"
					bind:value={code}
					required
					autocomplete="one-time-code"
					class="rounded-[var(--radius-sm)] border px-3 py-2.5 text-[15px] tracking-widest outline-none"
					style="background: var(--surface-sunk); border-color: var(--border); color: var(--text);"
				/>
				{#if error}
					<p class="text-sm" style="color: var(--danger);">{error}</p>
				{/if}
				<div class="flex gap-2">
					<button
						type="submit"
						disabled={loading}
						class="rounded-[var(--radius-sm)] px-3 py-2 text-sm font-medium text-white disabled:opacity-60"
						style="background: var(--accent);"
					>
						{loading ? 'Confirming…' : 'Confirm'}
					</button>
					<button
						type="button"
						onclick={() => {
							error = null;
							view = 'status';
						}}
						class="rounded-[var(--radius-sm)] border px-3 py-2 text-sm font-medium"
						style="border-color: var(--border); color: var(--text-muted);"
					>
						Cancel
					</button>
				</div>
			</form>
		{:else if view === 'recovery-codes'}
			<p class="mb-3 text-sm" style="color: var(--text-muted);">
				Save these recovery codes somewhere safe. Each one works once, and they won't be shown again.
			</p>
			<div
				class="mb-4 grid grid-cols-2 gap-2 rounded-[var(--radius-sm)] border p-3"
				style="background: var(--surface-sunk); border-color: var(--border);"
			>
				{#each recoveryCodes as recoveryCode (recoveryCode)}
					<code class="text-sm" style="color: var(--text);">{recoveryCode}</code>
				{/each}
			</div>
			<button
				onclick={doneWithRecoveryCodes}
				class="rounded-[var(--radius-sm)] px-3 py-2 text-sm font-medium text-white"
				style="background: var(--accent);"
			>
				I've saved these
			</button>
		{:else if view === 'disabling'}
			<p class="mb-3 text-sm" style="color: var(--text-muted);">
				Confirm your password to turn off two-factor authentication.
			</p>
			<form onsubmit={confirmDisable} class="flex flex-col gap-3">
				<input
					type="password"
					placeholder="Password"
					bind:value={disablePassword}
					required
					autocomplete="current-password"
					class="rounded-[var(--radius-sm)] border px-3 py-2.5 text-[15px] outline-none"
					style="background: var(--surface-sunk); border-color: var(--border); color: var(--text);"
				/>
				{#if error}
					<p class="text-sm" style="color: var(--danger);">{error}</p>
				{/if}
				<div class="flex gap-2">
					<button
						type="submit"
						disabled={loading}
						class="rounded-[var(--radius-sm)] px-3 py-2 text-sm font-medium text-white disabled:opacity-60"
						style="background: var(--danger);"
					>
						{loading ? 'Disabling…' : 'Disable'}
					</button>
					<button
						type="button"
						onclick={() => {
							error = null;
							disablePassword = '';
							view = 'status';
						}}
						class="rounded-[var(--radius-sm)] border px-3 py-2 text-sm font-medium"
						style="border-color: var(--border); color: var(--text-muted);"
					>
						Cancel
					</button>
				</div>
			</form>
		{/if}
	</section>
</div>
