<script lang="ts">
	import { fade } from 'svelte/transition';
	import {
		PlusIcon,
		TrashIcon,
		GlobeIcon,
		CaretDownIcon,
		SealCheckIcon,
		WarningCircleIcon,
		CopyIcon,
		CheckCircleIcon,
		ArrowClockwiseIcon
	} from 'phosphor-svelte';
	import { adminSession } from '$lib/adminSession.svelte';
	import {
		listDomains,
		createDomain,
		setCatchAll,
		deleteDomain,
		listAccounts,
		getDomainDkim,
		verifyDomain,
		type DomainObject,
		type AccountObject,
		type DkimRecord
	} from '$lib/admin';

	let domains = $state<DomainObject[]>([]);
	let accounts = $state<AccountObject[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);

	let newName = $state('');
	let creating = $state(false);
	let createError = $state<string | null>(null);

	let catchAllDrafts = $state<Record<number, string>>({});

	// DNS setup panel: which domain is expanded, its fetched DKIM record
	// (fetched lazily on first expand, not for every domain up front --
	// generates a keypair on first call), and per-domain verify state.
	let dnsPanelOpenFor = $state<number | null>(null);
	let dkimRecords = $state<Record<number, DkimRecord>>({});
	let dkimLoading = $state<number | null>(null);
	let verifying = $state<number | null>(null);
	let verifyMessage = $state<Record<number, string>>({});
	let copiedKey = $state<string | null>(null);

	async function refresh() {
		const token = adminSession.token;
		if (!token) return;
		loading = true;
		try {
			[domains, accounts] = await Promise.all([listDomains(token), listAccounts(token)]);
			for (const d of domains) {
				catchAllDrafts[d.id] = d.catchAllLocalPart ?? '';
			}
			error = null;
		} catch {
			error = 'Could not load domains.';
		} finally {
			loading = false;
		}
	}

	function localPartsForDomain(domainName: string): string[] {
		const suffix = `@${domainName}`;
		return accounts.filter((a) => a.address.endsWith(suffix)).map((a) => a.address.slice(0, -suffix.length));
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
			await createDomain(token, newName.trim(), null);
			newName = '';
			await refresh();
		} catch {
			createError = 'Could not add that domain (it may already exist).';
		} finally {
			creating = false;
		}
	}

	async function saveCatchAll(domain: DomainObject) {
		const token = adminSession.token;
		if (!token) return;
		const value = catchAllDrafts[domain.id]?.trim() || null;
		if (value === domain.catchAllLocalPart) return;
		try {
			await setCatchAll(token, domain.id, value);
			await refresh();
		} catch {
			error = 'Could not update the catch-all.';
		}
	}

	async function handleDelete(domain: DomainObject) {
		const token = adminSession.token;
		if (!token) return;
		if (!confirm(`Stop hosting ${domain.name}? This does not delete its accounts.`)) return;
		try {
			await deleteDomain(token, domain.id);
			await refresh();
		} catch {
			error = 'Could not remove that domain.';
		}
	}

	async function toggleDnsPanel(domain: DomainObject) {
		const token = adminSession.token;
		if (!token) return;
		if (dnsPanelOpenFor === domain.id) {
			dnsPanelOpenFor = null;
			return;
		}
		dnsPanelOpenFor = domain.id;
		if (!dkimRecords[domain.id]) {
			dkimLoading = domain.id;
			try {
				dkimRecords[domain.id] = await getDomainDkim(token, domain.id);
			} catch {
				error = 'Could not load the DKIM record.';
			} finally {
				dkimLoading = null;
			}
		}
	}

	async function handleVerify(domain: DomainObject) {
		const token = adminSession.token;
		if (!token || verifying !== null) return;
		verifying = domain.id;
		delete verifyMessage[domain.id];
		try {
			const result = await verifyDomain(token, domain.id);
			if (result.verified) {
				domains = domains.map((d) => (d.id === domain.id ? { ...d, verified: true } : d));
			} else {
				verifyMessage[domain.id] = "Didn't find that TXT record yet -- DNS changes can take a while to propagate.";
			}
		} catch {
			verifyMessage[domain.id] = 'Could not check DNS right now.';
		} finally {
			verifying = null;
		}
	}

	async function copyToClipboard(key: string, value: string) {
		try {
			await navigator.clipboard.writeText(value);
			copiedKey = key;
			setTimeout(() => {
				if (copiedKey === key) copiedKey = null;
			}, 1500);
		} catch {
			// Clipboard API unavailable (e.g. insecure context) -- the value
			// is still selectable/copyable by hand from the field itself.
		}
	}
</script>

<div class="flex flex-col gap-6">
	<div>
		<h2 class="mb-1 text-base font-semibold" style="color: var(--text);">Domains</h2>
		<p class="text-sm" style="color: var(--text-muted);">
			Domains this server hosts mail for, and each one's catch-all address.
		</p>
	</div>

	<form
		onsubmit={handleCreate}
		class="flex flex-col gap-2 rounded-[var(--radius)] p-4 sm:flex-row sm:items-end"
		style="background: var(--surface); border: 1px solid var(--border);"
	>
		<div class="flex-1">
			<label class="mb-1 block text-xs" style="color: var(--text-faint);" for="domain-name">Domain</label>
			<input
				id="domain-name"
				type="text"
				placeholder="example.com"
				bind:value={newName}
				required
				class="w-full rounded-[var(--radius-sm)] border px-3 py-2 text-[14px] outline-none"
				style="background: var(--surface-sunk); border-color: var(--border); color: var(--text);"
			/>
		</div>
		<button
			type="submit"
			disabled={creating}
			class="flex items-center justify-center gap-1.5 rounded-[var(--radius-sm)] px-4 py-2 text-[14px] font-medium text-white transition-opacity disabled:opacity-60"
			style="background: var(--accent);"
		>
			<PlusIcon size={16} weight="bold" />
			Add
		</button>
	</form>
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
	{:else if domains.length === 0}
		<div class="flex flex-col items-center gap-4 py-16 text-center" in:fade={{ duration: 200 }}>
			<div class="flex h-16 w-16 items-center justify-center rounded-full" style="background: var(--surface-sunk);">
				<GlobeIcon size={28} style="color: var(--text-faint);" />
			</div>
			<p class="text-sm" style="color: var(--text-faint);">No domains hosted yet.</p>
		</div>
	{:else}
		<ul class="flex flex-col gap-2">
			{#each domains as domain (domain.id)}
				<li class="rounded-[var(--radius)]" style="background: var(--surface); border: 1px solid var(--border);">
					<div class="flex flex-col gap-2 p-3.5 sm:flex-row sm:items-center">
						<div class="flex min-w-0 flex-1 items-center gap-2">
							<span class="truncate text-[15px] font-medium" style="color: var(--text);">{domain.name}</span>
							{#if domain.verified}
								<span
									class="flex shrink-0 items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium"
									style="color: var(--success); background: color-mix(in oklch, var(--success) 15%, transparent);"
								>
									<SealCheckIcon size={12} weight="fill" />
									Verified
								</span>
							{:else}
								<button
									onclick={() => toggleDnsPanel(domain)}
									class="flex shrink-0 items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium transition-colors hover:bg-[var(--surface-hover)]"
									style="color: var(--text-faint); background: var(--surface-sunk);"
								>
									<WarningCircleIcon size={12} />
									Unverified
								</button>
							{/if}
						</div>
						<div class="flex flex-wrap items-center gap-2">
							<span class="shrink-0 text-xs" style="color: var(--text-faint);">catch-all</span>
							<div class="relative min-w-0 flex-1 sm:w-40 sm:flex-none">
								<select
									bind:value={catchAllDrafts[domain.id]}
									onchange={() => saveCatchAll(domain)}
									class="w-full appearance-none rounded-[var(--radius-sm)] border py-1.5 pr-8 pl-2.5 text-[13px] outline-none"
									style="background: var(--surface-sunk); border-color: var(--border); color: var(--text);"
								>
									<option value="">None</option>
									{#each localPartsForDomain(domain.name) as localPart (localPart)}
										<option value={localPart}>{localPart}</option>
									{/each}
									{#if domain.catchAllLocalPart && !localPartsForDomain(domain.name).includes(domain.catchAllLocalPart)}
										<option value={domain.catchAllLocalPart}>{domain.catchAllLocalPart} (account deleted)</option>
									{/if}
								</select>
								<CaretDownIcon
									size={12}
									class="pointer-events-none absolute top-1/2 right-2.5 -translate-y-1/2"
									style="color: var(--text-faint);"
								/>
							</div>
							<button
								onclick={() => toggleDnsPanel(domain)}
								class="shrink-0 rounded-[var(--radius-sm)] px-3 py-1.5 text-xs font-medium transition-colors hover:bg-[var(--surface-hover)]"
								style="color: var(--text-muted); background: var(--surface-sunk);"
							>
								DNS setup
							</button>
							<button
								onclick={() => handleDelete(domain)}
								aria-label={`Remove ${domain.name}`}
								class="flex h-11 w-11 shrink-0 items-center justify-center rounded-full text-[var(--danger)] transition-colors hover:bg-[var(--surface-hover)]"
							>
								<TrashIcon size={16} />
							</button>
						</div>
					</div>

					{#if dnsPanelOpenFor === domain.id}
						<div class="flex flex-col gap-4 px-3.5 pb-4" transition:fade={{ duration: 150 }}>
							<div class="rounded-[var(--radius-sm)] p-3" style="background: var(--surface-sunk);">
								<div class="mb-2 flex items-center justify-between gap-2">
									<span class="text-xs font-medium" style="color: var(--text-muted);">DKIM record</span>
									{#if dkimLoading === domain.id}
										<ArrowClockwiseIcon size={14} class="animate-spin" style="color: var(--text-faint);" />
									{/if}
								</div>
								{#if dkimRecords[domain.id]}
									{@const dkim = dkimRecords[domain.id]}
									<div class="flex flex-col gap-2 font-mono text-xs">
										<div class="flex items-center gap-2">
											<span class="w-16 shrink-0" style="color: var(--text-faint);">Type</span>
											<span style="color: var(--text);">TXT</span>
										</div>
										<div class="flex items-start gap-2">
											<span class="w-16 shrink-0 pt-0.5" style="color: var(--text-faint);">Name</span>
											<span class="min-w-0 flex-1 break-all" style="color: var(--text);">{dkim.recordName}</span>
											<button
												onclick={() => copyToClipboard(`dkim-name-${domain.id}`, dkim.recordName)}
												aria-label="Copy record name"
												class="shrink-0 rounded p-1 transition-colors hover:bg-[var(--surface-hover)]"
											>
												{#if copiedKey === `dkim-name-${domain.id}`}
													<CheckCircleIcon size={14} weight="fill" style="color: var(--success);" />
												{:else}
													<CopyIcon size={14} style="color: var(--text-faint);" />
												{/if}
											</button>
										</div>
										<div class="flex items-start gap-2">
											<span class="w-16 shrink-0 pt-0.5" style="color: var(--text-faint);">Value</span>
											<span class="min-w-0 flex-1 break-all" style="color: var(--text);">{dkim.recordValue}</span>
											<button
												onclick={() => copyToClipboard(`dkim-value-${domain.id}`, dkim.recordValue)}
												aria-label="Copy record value"
												class="shrink-0 rounded p-1 transition-colors hover:bg-[var(--surface-hover)]"
											>
												{#if copiedKey === `dkim-value-${domain.id}`}
													<CheckCircleIcon size={14} weight="fill" style="color: var(--success);" />
												{:else}
													<CopyIcon size={14} style="color: var(--text-faint);" />
												{/if}
											</button>
										</div>
									</div>
								{/if}
							</div>

							<div class="rounded-[var(--radius-sm)] p-3" style="background: var(--surface-sunk);">
								<div class="mb-2 flex items-center justify-between gap-2">
									<span class="text-xs font-medium" style="color: var(--text-muted);">
										Ownership verification (optional)
									</span>
									<button
										onclick={() => handleVerify(domain)}
										disabled={verifying === domain.id}
										class="flex shrink-0 items-center gap-1.5 rounded-[var(--radius-sm)] px-3 py-1.5 text-xs font-medium text-white transition-opacity disabled:opacity-60"
										style="background: var(--accent);"
									>
										<ArrowClockwiseIcon size={13} class={verifying === domain.id ? 'animate-spin' : ''} />
										Verify now
									</button>
								</div>
								<p class="mb-2 text-xs" style="color: var(--text-faint);">
									This doesn't gate anything -- it's just a way to confirm your own DNS is set up
									correctly before you find out the hard way.
								</p>
								<div class="flex flex-col gap-2 font-mono text-xs">
									<div class="flex items-center gap-2">
										<span class="w-16 shrink-0" style="color: var(--text-faint);">Type</span>
										<span style="color: var(--text);">TXT</span>
									</div>
									<div class="flex items-start gap-2">
										<span class="w-16 shrink-0 pt-0.5" style="color: var(--text-faint);">Name</span>
										<span class="min-w-0 flex-1 break-all" style="color: var(--text);"
											>_litterae-challenge.{domain.name}</span
										>
										<button
											onclick={() =>
												copyToClipboard(`verify-name-${domain.id}`, `_litterae-challenge.${domain.name}`)}
											aria-label="Copy record name"
											class="shrink-0 rounded p-1 transition-colors hover:bg-[var(--surface-hover)]"
										>
											{#if copiedKey === `verify-name-${domain.id}`}
												<CheckCircleIcon size={14} weight="fill" style="color: var(--success);" />
											{:else}
												<CopyIcon size={14} style="color: var(--text-faint);" />
											{/if}
										</button>
									</div>
									<div class="flex items-start gap-2">
										<span class="w-16 shrink-0 pt-0.5" style="color: var(--text-faint);">Value</span>
										<span class="min-w-0 flex-1 break-all" style="color: var(--text);"
											>litterae-verify={domain.verificationToken}</span
										>
										<button
											onclick={() =>
												copyToClipboard(
													`verify-value-${domain.id}`,
													`litterae-verify=${domain.verificationToken}`
												)}
											aria-label="Copy record value"
											class="shrink-0 rounded p-1 transition-colors hover:bg-[var(--surface-hover)]"
										>
											{#if copiedKey === `verify-value-${domain.id}`}
												<CheckCircleIcon size={14} weight="fill" style="color: var(--success);" />
											{:else}
												<CopyIcon size={14} style="color: var(--text-faint);" />
											{/if}
										</button>
									</div>
								</div>
								{#if verifyMessage[domain.id]}
									<p class="mt-2 text-xs" style="color: var(--text-muted);">{verifyMessage[domain.id]}</p>
								{/if}
							</div>
						</div>
					{/if}
				</li>
			{/each}
		</ul>
	{/if}
</div>
