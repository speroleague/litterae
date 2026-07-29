<script lang="ts">
	import { TrashIcon } from 'phosphor-svelte';
	import { session } from '$lib/session.svelte';
	import { createContact, updateContact, deleteContact, JmapError, type ContactObject } from '$lib/jmap';
	import { loadContacts } from '$lib/contactsState.svelte';
	import { showToast } from '$lib/toast.svelte';
	import Dialog from './Dialog.svelte';

	let {
		open = $bindable(false),
		contact = null,
		initialName = '',
		initialEmail = '',
		onClose
	}: {
		open?: boolean;
		/** Editing an existing contact vs. creating a new one. */
		contact?: ContactObject | null;
		/** Prefilled values when creating from a message address. */
		initialName?: string;
		initialEmail?: string;
		onClose?: () => void;
	} = $props();

	let name = $state('');
	let email = $state('');
	let saving = $state(false);

	$effect(() => {
		if (open) {
			name = contact?.name ?? initialName;
			email = contact?.email ?? initialEmail;
		}
	});

	function close() {
		open = false;
		onClose?.();
	}

	async function handleSave(e: SubmitEvent) {
		e.preventDefault();
		const token = session.token;
		const accountId = session.accountId;
		if (!token || !accountId || saving) return;
		saving = true;
		try {
			if (contact) {
				await updateContact(token, accountId, contact.id, { name: name.trim(), email: email.trim() });
			} else {
				await createContact(token, accountId, { name: name.trim() || undefined, email: email.trim() });
			}
			await loadContacts();
			close();
		} catch (err) {
			showToast(err instanceof JmapError ? err.message : 'Could not save this contact.');
		} finally {
			saving = false;
		}
	}

	async function handleDelete() {
		const token = session.token;
		const accountId = session.accountId;
		if (!token || !accountId || !contact || saving) return;
		if (!confirm(`Remove ${contact.name || contact.email} from contacts?`)) return;
		saving = true;
		try {
			await deleteContact(token, accountId, contact.id);
			await loadContacts();
			close();
		} catch {
			showToast('Could not remove this contact.');
		} finally {
			saving = false;
		}
	}
</script>

<Dialog bind:open {onClose}>
	<form onsubmit={handleSave} class="flex flex-col gap-4">
		<h2 class="text-base font-semibold" style="color: var(--text);">
			{contact ? 'Edit Contact' : 'Add Contact'}
		</h2>
		<div>
			<label class="mb-1 block text-xs" style="color: var(--text-faint);" for="contact-name">Name</label>
			<input
				id="contact-name"
				type="text"
				placeholder="Alice Example"
				bind:value={name}
				class="w-full rounded-[var(--radius-sm)] border px-3 py-2 text-[14px] outline-none"
				style="background: var(--surface-sunk); border-color: var(--border); color: var(--text);"
			/>
		</div>
		<div>
			<label class="mb-1 block text-xs" style="color: var(--text-faint);" for="contact-email">Email</label>
			<input
				id="contact-email"
				type="email"
				placeholder="alice@example.com"
				bind:value={email}
				required
				class="w-full rounded-[var(--radius-sm)] border px-3 py-2 text-[14px] outline-none"
				style="background: var(--surface-sunk); border-color: var(--border); color: var(--text);"
			/>
		</div>
		<div class="flex items-center justify-between gap-2">
			{#if contact}
				<button
					type="button"
					onclick={handleDelete}
					disabled={saving}
					aria-label="Remove contact"
					class="flex h-9 w-9 items-center justify-center rounded-full text-[var(--danger)] transition-colors hover:bg-[var(--surface-hover)] disabled:opacity-50"
				>
					<TrashIcon size={16} />
				</button>
			{:else}
				<span></span>
			{/if}
			<div class="flex items-center gap-2">
				<button
					type="button"
					onclick={close}
					class="rounded-[var(--radius-sm)] px-3.5 py-2 text-[14px] font-medium"
					style="color: var(--text-muted); background: var(--surface-sunk);"
				>
					Cancel
				</button>
				<button
					type="submit"
					disabled={saving}
					class="rounded-[var(--radius-sm)] px-3.5 py-2 text-[14px] font-medium text-white transition-opacity disabled:opacity-60"
					style="background: var(--accent);"
				>
					{saving ? 'Saving…' : 'Save'}
				</button>
			</div>
		</div>
	</form>
</Dialog>
