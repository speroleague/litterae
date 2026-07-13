<script lang="ts">
	import { fade } from 'svelte/transition';
	import { PlusIcon, TrashIcon, UsersIcon, CaretDownIcon } from 'phosphor-svelte';
	import { adminSession } from '$lib/adminSession.svelte';
	import { listAccounts, createAccount, deleteAccount, listDomains, type AccountObject, type DomainObject } from '$lib/admin';

	let accounts = $state<AccountObject[]>([]);
	let domains = $state<DomainObject[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);

	let newLocalPart = $state('');
	let newDomain = $state('');
	let newPassword = $state('');
	let creating = $state(false);
	let createError = $state<string | null>(null);

	async function refresh() {
		const token = adminSession.token;
		if (!token) return;
		loading = true;
		try {
			[accounts, domains] = await Promise.all([listAccounts(token), listDomains(token)]);
			if (!newDomain && domains.length > 0) newDomain = domains[0].name;
			error = null;
		} catch {
			error = 'Could not load accounts.';
		} finally {
			loading = false;
		}
	}

	$effect(() => {
		refresh();
	});

	async function handleCreate(e: SubmitEvent) {
		e.preventDefault();
		const token = adminSession.token;
		if (!token) return;
		createError = null;
		creating = true;
		try {
			await createAccount(token, newLocalPart.trim(), newDomain, newPassword);
			newLocalPart = '';
			newPassword = '';
			await refresh();
		} catch {
			createError = 'Could not create that account (address may already exist).';
		} finally {
			creating = false;
		}
	}

	async function handleDelete(account: AccountObject) {
		const token = adminSession.token;
		if (!token) return;
		if (!confirm(`Delete ${account.address}? This permanently removes its mail.`)) return;
		try {
			await deleteAccount(token, account.id);
			await refresh();
		} catch {
			error = 'Could not delete that account.';
		}
	}
</script>

<div class="flex flex-col gap-6">
	<div>
		<h2 class="mb-1 text-base font-semibold" style="color: var(--text);">Accounts</h2>
		<p class="text-sm" style="color: var(--text-muted);">Mailboxes hosted on this server.</p>
	</div>

	<form
		onsubmit={handleCreate}
		class="flex flex-col gap-2 rounded-[var(--radius)] p-4 sm:flex-row sm:items-end"
		style="background: var(--surface); border: 1px solid var(--border);"
	>
		<div class="flex-1">
			<label class="mb-1 block text-xs" style="color: var(--text-faint);" for="account-local">Address</label>
			<div class="flex items-center gap-1">
				<input
					id="account-local"
					type="text"
					placeholder="alice"
					bind:value={newLocalPart}
					required
					class="w-full rounded-[var(--radius-sm)] border px-3 py-2 text-[14px] outline-none"
					style="background: var(--surface-sunk); border-color: var(--border); color: var(--text);"
				/>
				<span style="color: var(--text-faint);">@</span>
				<div class="relative">
					<select
						bind:value={newDomain}
						required
						class="appearance-none rounded-[var(--radius-sm)] border py-2 pr-7 pl-2 text-[14px] outline-none"
						style="background: var(--surface-sunk); border-color: var(--border); color: var(--text);"
					>
						{#each domains as domain (domain.id)}
							<option value={domain.name}>{domain.name}</option>
						{/each}
					</select>
					<CaretDownIcon
						size={12}
						class="pointer-events-none absolute top-1/2 right-2 -translate-y-1/2"
						style="color: var(--text-faint);"
					/>
				</div>
			</div>
		</div>
		<div class="flex-1">
			<label class="mb-1 block text-xs" style="color: var(--text-faint);" for="account-password">Password</label>
			<input
				id="account-password"
				type="password"
				placeholder="Temporary password"
				bind:value={newPassword}
				required
				autocomplete="new-password"
				class="w-full rounded-[var(--radius-sm)] border px-3 py-2 text-[14px] outline-none"
				style="background: var(--surface-sunk); border-color: var(--border); color: var(--text);"
			/>
		</div>
		<button
			type="submit"
			disabled={creating || domains.length === 0}
			class="flex items-center justify-center gap-1.5 rounded-[var(--radius-sm)] px-4 py-2 text-[14px] font-medium text-white transition-opacity disabled:opacity-60"
			style="background: var(--accent);"
		>
			<PlusIcon size={16} weight="bold" />
			Add
		</button>
	</form>
	{#if domains.length === 0 && !loading}
		<p class="-mt-4 text-sm" style="color: var(--text-faint);">Add a domain first before creating accounts.</p>
	{/if}
	{#if createError}
		<p class="-mt-4 text-sm" style="color: var(--danger);">{createError}</p>
	{/if}

	{#if loading}
		<div class="flex animate-pulse flex-col gap-2">
			{#each Array(3) as _}
				<div class="h-14 rounded-[var(--radius)]" style="background: var(--surface-sunk);"></div>
			{/each}
		</div>
	{:else if error}
		<p class="text-sm" style="color: var(--danger);">{error}</p>
	{:else if accounts.length === 0}
		<div class="flex flex-col items-center gap-4 py-16 text-center" in:fade={{ duration: 200 }}>
			<div class="flex h-16 w-16 items-center justify-center rounded-full" style="background: var(--surface-sunk);">
				<UsersIcon size={28} style="color: var(--text-faint);" />
			</div>
			<p class="text-sm" style="color: var(--text-faint);">No accounts yet.</p>
		</div>
	{:else}
		<ul class="flex flex-col gap-2">
			{#each accounts as account (account.id)}
				<li
					class="flex items-center justify-between gap-2 rounded-[var(--radius)] p-3.5"
					style="background: var(--surface); border: 1px solid var(--border);"
				>
					<div class="min-w-0">
						<div class="truncate text-[15px] font-medium" style="color: var(--text);">{account.address}</div>
						<div class="text-xs" style="color: var(--text-faint);">
							{new Date(account.createdAt * 1000).toLocaleDateString()}
						</div>
					</div>
					<button
						onclick={() => handleDelete(account)}
						aria-label={`Delete ${account.address}`}
						class="flex h-11 w-11 shrink-0 items-center justify-center rounded-full text-[var(--danger)] transition-colors hover:bg-[var(--surface-hover)]"
					>
						<TrashIcon size={16} />
					</button>
				</li>
			{/each}
		</ul>
	{/if}
</div>
