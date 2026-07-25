<script lang="ts">
	// A single From/To address in the message view: a link back to its
	// contact if one already exists, or plain text plus a small "add to
	// contacts" affordance if not -- reusing `ContactFormDialog` for both
	// the "edit" and "create, prefilled from this address" flows.
	import { UserPlusIcon } from 'phosphor-svelte';
	import { contactsState } from '$lib/contactsState.svelte';
	import ContactFormDialog from './ContactFormDialog.svelte';

	let {
		addr,
		muted = false
	}: { addr: { name: string | null; email: string }; muted?: boolean } = $props();

	let dialogOpen = $state(false);

	const contact = $derived(contactsState.byEmail.get(addr.email.toLowerCase()) ?? null);
	const label = $derived(addr.name ? `${addr.name} <${addr.email}>` : addr.email);
</script>

{#if contact}
	<button type="button" onclick={() => (dialogOpen = true)} class="hover:underline" style="color: var(--accent);">
		{label}
	</button>
{:else}
	<span style={muted ? 'color: var(--text-faint);' : 'color: var(--text);'}>{label}</span>
	<button
		type="button"
		onclick={() => (dialogOpen = true)}
		aria-label={`Add ${addr.email} to contacts`}
		class="inline-flex h-5 w-5 items-center justify-center rounded-full align-text-bottom transition-colors hover:bg-[var(--surface-hover)]"
		style="color: var(--text-faint);"
	>
		<UserPlusIcon size={13} />
	</button>
{/if}

<ContactFormDialog bind:open={dialogOpen} {contact} initialName={addr.name ?? ''} initialEmail={addr.email} />
