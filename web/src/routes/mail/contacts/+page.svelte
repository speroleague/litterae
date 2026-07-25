<script lang="ts">
	import { goto } from '$app/navigation';
	import { fade } from 'svelte/transition';
	import { CaretLeftIcon, MagnifyingGlassIcon, PlusIcon, UsersIcon, CaretRightIcon } from 'phosphor-svelte';
	import { session } from '$lib/session.svelte';
	import { contactsState, loadContacts } from '$lib/contactsState.svelte';
	import type { ContactObject } from '$lib/jmap';
	import ContactFormDialog from '$lib/ContactFormDialog.svelte';

	let loading = $state(true);
	let search = $state('');
	let dialogOpen = $state(false);
	let editingContact = $state<ContactObject | null>(null);

	$effect(() => {
		if (!session.isUnlocked) return;
		loadContacts().finally(() => (loading = false));
	});

	const filtered = $derived(
		(() => {
			const q = search.trim().toLowerCase();
			const list = q
				? contactsState.contacts.filter(
						(c) => (c.name ?? '').toLowerCase().includes(q) || c.email.toLowerCase().includes(q)
					)
				: contactsState.contacts;
			return [...list].sort((a, b) => (a.name || a.email).localeCompare(b.name || b.email));
		})()
	);

	function openCreate() {
		editingContact = null;
		dialogOpen = true;
	}

	function openEdit(contact: ContactObject) {
		editingContact = contact;
		dialogOpen = true;
	}
</script>

<div class="mx-auto flex min-h-screen max-w-2xl flex-col">
	<header class="flex items-center gap-2 px-2 py-3" style="border-bottom: 1px solid var(--border);">
		<button
			onclick={() => goto('/mail')}
			aria-label="Back"
			class="flex h-11 w-11 items-center justify-center rounded-full transition-colors hover:bg-[var(--surface-hover)]"
			style="color: var(--text-muted);"
		>
			<CaretLeftIcon size={20} />
		</button>
		<h1 class="flex-1 text-[15px] font-semibold" style="color: var(--text);">Contacts</h1>
		<button
			onclick={openCreate}
			aria-label="Add contact"
			class="flex h-11 w-11 items-center justify-center rounded-full transition-colors hover:bg-[var(--surface-hover)]"
			style="color: var(--text-muted);"
		>
			<PlusIcon size={20} />
		</button>
	</header>

	<main class="flex-1 px-5 py-5">
		<div class="mb-4 flex items-center gap-2 rounded-[var(--radius-sm)] px-3 py-2" style="background: var(--surface-sunk); border: 1px solid var(--border);">
			<MagnifyingGlassIcon size={16} style="color: var(--text-faint);" />
			<input
				type="text"
				placeholder="Search contacts"
				bind:value={search}
				class="min-w-0 flex-1 bg-transparent text-[14px] outline-none"
				style="color: var(--text);"
			/>
		</div>

		{#if loading}
			<div class="flex animate-pulse flex-col gap-2">
				{#each Array(4) as _}
					<div class="h-14 rounded-[var(--radius)]" style="background: var(--surface-sunk);"></div>
				{/each}
			</div>
		{:else if filtered.length === 0}
			<div class="flex flex-col items-center gap-4 py-16 text-center" in:fade={{ duration: 200 }}>
				<div class="flex h-16 w-16 items-center justify-center rounded-full" style="background: var(--surface-sunk);">
					<UsersIcon size={28} style="color: var(--text-faint);" />
				</div>
				<p class="text-sm" style="color: var(--text-faint);">
					{contactsState.contacts.length === 0 ? 'No contacts yet.' : 'No contacts match your search.'}
				</p>
			</div>
		{:else}
			<ul class="flex flex-col gap-2">
				{#each filtered as contact (contact.id)}
					<li>
						<button
							onclick={() => openEdit(contact)}
							class="flex w-full items-center justify-between gap-2 rounded-[var(--radius)] p-3.5 text-left transition-colors hover:bg-[var(--surface-hover)]"
							style="background: var(--surface); border: 1px solid var(--border);"
						>
							<div class="min-w-0">
								<div class="truncate text-[15px] font-medium" style="color: var(--text);">
									{contact.name || contact.email}
								</div>
								{#if contact.name}
									<div class="truncate text-xs" style="color: var(--text-faint);">{contact.email}</div>
								{/if}
							</div>
							<CaretRightIcon size={16} style="color: var(--text-faint);" />
						</button>
					</li>
				{/each}
			</ul>
		{/if}
	</main>
</div>

<ContactFormDialog bind:open={dialogOpen} contact={editingContact} />
