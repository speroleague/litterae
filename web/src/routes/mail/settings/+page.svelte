<script lang="ts">
	import { goto } from '$app/navigation';
	import { CaretLeftIcon, CheckIcon, KeyIcon, CopyIcon, TrashIcon } from 'phosphor-svelte';
	import { session } from '$lib/session.svelte';
	import {
		getIdentity,
		setIdentitySignature,
		listAppPasswords,
		createAppPassword,
		revokeAppPassword,
		type AppPasswordSummary
	} from '$lib/jmap';
	import { setSignature } from '$lib/composeState.svelte';
	import { showToast } from '$lib/toast.svelte';

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
		try {
			await setIdentitySignature(token, accountId, identityId, text);
			setSignature(text);
			saved = true;
			setTimeout(() => (saved = false), 2000);
		} catch {
			showToast('Could not save your signature.');
		} finally {
			saving = false;
		}
	}

	let appPasswords = $state<AppPasswordSummary[]>([]);
	let appPasswordsLoading = $state(true);
	let creatingAppPassword = $state(false);
	let newLabel = $state('');
	let newScope = $state<'full' | 'submission'>('full');
	let revealedPassword = $state<string | null>(null);

	async function loadAppPasswords() {
		const token = session.token;
		if (!token) return;
		try {
			appPasswords = await listAppPasswords(token);
		} catch {
			showToast('Could not load app passwords.');
		} finally {
			appPasswordsLoading = false;
		}
	}

	$effect(() => {
		if (session.token) loadAppPasswords();
	});

	async function handleCreateAppPassword(e: SubmitEvent) {
		e.preventDefault();
		const token = session.token;
		if (!token || creatingAppPassword) return;
		const label = newLabel.trim();
		if (!label) return;
		creatingAppPassword = true;
		try {
			const created = await createAppPassword(token, label, newScope);
			revealedPassword = created.password;
			newLabel = '';
			await loadAppPasswords();
		} catch {
			showToast('Could not create an app password.');
		} finally {
			creatingAppPassword = false;
		}
	}

	async function handleRevoke(id: number) {
		const token = session.token;
		if (!token) return;
		if (!confirm('Revoke this app password? Anything using it will stop working immediately.')) return;
		try {
			await revokeAppPassword(token, id);
			await loadAppPasswords();
		} catch {
			showToast('Could not revoke this app password.');
		}
	}

	function formatDate(unixSeconds: number): string {
		return new Date(unixSeconds * 1000).toLocaleDateString(undefined, { dateStyle: 'medium' });
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
		<h1 class="text-[15px] font-semibold" style="color: var(--text);">Settings</h1>
	</header>

	<main class="flex-1 px-5 py-5">
		<h2 class="mb-2 text-sm font-semibold" style="color: var(--text);">Signature</h2>
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

		<h2 class="mt-8 mb-2 flex items-center gap-1.5 text-sm font-semibold" style="color: var(--text);">
			<KeyIcon size={16} />
			App Passwords
		</h2>
		<p class="mb-3 text-sm" style="color: var(--text-faint);">
			Separate passwords for other apps or devices -- revoke one without changing your main
			password. "Send only" can submit mail but can't sign in and read your mailbox.
		</p>

		{#if revealedPassword}
			<div
				class="mb-4 rounded-[var(--radius)] p-3"
				style="background: var(--accent-weak); border: 1px solid var(--accent);"
			>
				<p class="mb-2 text-sm" style="color: var(--text);">
					Copy this now -- it won't be shown again.
				</p>
				<div class="flex items-center justify-between gap-2 rounded-[var(--radius-sm)] border px-3 py-2" style="background: var(--surface); border-color: var(--border);">
					<code class="truncate text-sm" style="color: var(--text);">{revealedPassword}</code>
					<button
						aria-label="Copy password"
						onclick={() => navigator.clipboard.writeText(revealedPassword ?? '')}
						class="shrink-0"
						style="color: var(--text-muted);"
					>
						<CopyIcon size={16} />
					</button>
				</div>
				<button
					onclick={() => (revealedPassword = null)}
					class="mt-2 text-sm font-medium"
					style="color: var(--accent);"
				>
					Done
				</button>
			</div>
		{/if}

		{#if appPasswordsLoading}
			<div class="h-16 animate-pulse rounded-[var(--radius)]" style="background: var(--surface-sunk);"></div>
		{:else}
			{#if appPasswords.length > 0}
				<ul class="mb-4 flex flex-col gap-2">
					{#each appPasswords as appPassword (appPassword.id)}
						<li
							class="flex items-center justify-between gap-2 rounded-[var(--radius-sm)] border px-3 py-2"
							style="border-color: var(--border);"
						>
							<div class="min-w-0">
								<div class="flex items-center gap-2">
									<span class="truncate text-sm font-medium" style="color: var(--text);">{appPassword.label}</span>
									<span
										class="shrink-0 rounded-full px-1.5 py-0.5 text-[11px] font-medium"
										style="background: var(--surface-sunk); color: var(--text-muted);"
									>
										{appPassword.scope === 'full' ? 'Full access' : 'Send only'}
									</span>
								</div>
								<p class="text-xs" style="color: var(--text-faint);">
									Created {formatDate(appPassword.createdAt)}
									{#if appPassword.lastUsedAt}
										· last used {formatDate(appPassword.lastUsedAt)}
									{:else}
										· never used
									{/if}
								</p>
							</div>
							<button
								onclick={() => handleRevoke(appPassword.id)}
								aria-label={`Revoke ${appPassword.label}`}
								class="flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-[var(--danger)] transition-colors hover:bg-[var(--surface-hover)]"
							>
								<TrashIcon size={16} />
							</button>
						</li>
					{/each}
				</ul>
			{/if}

			<form onsubmit={handleCreateAppPassword} class="flex flex-col gap-2 sm:flex-row sm:items-center">
				<input
					type="text"
					placeholder="Label, e.g. Thunderbird"
					bind:value={newLabel}
					required
					class="rounded-[var(--radius-sm)] border px-3 py-2 text-[14px] outline-none sm:flex-1"
					style="background: var(--surface-sunk); border-color: var(--border); color: var(--text); max-width: 32ch;"
				/>
				<select
					bind:value={newScope}
					class="rounded-[var(--radius-sm)] border px-3 py-2 text-[14px] outline-none"
					style="background: var(--surface-sunk); border-color: var(--border); color: var(--text);"
				>
					<option value="full">Full access</option>
					<option value="submission">Send only</option>
				</select>
				<button
					type="submit"
					disabled={creatingAppPassword}
					class="rounded-[var(--radius-sm)] px-4 py-2 text-[14px] font-medium text-white transition-opacity disabled:opacity-60"
					style="background: var(--accent);"
				>
					{creatingAppPassword ? 'Creating…' : 'Create'}
				</button>
			</form>
		{/if}
	</main>
</div>
