<script lang="ts">
	// Suggestion dropdown layered over a plain comma-separated address
	// input -- `value` stays the same string `composeState.to/cc/bcc`
	// already used, in the same "Name <email>, email, ..." format
	// `parseAddressList` expects, so nothing downstream of Compose needs
	// to change. Typing a plain address and pressing Enter/comma with no
	// suggestion highlighted behaves exactly as it did before this
	// component existed -- only Enter/Tab while a suggestion is
	// highlighted is intercepted.
	import { contactsState } from '$lib/contactsState.svelte';
	import type { ContactObject } from '$lib/jmap';

	let {
		value = $bindable(''),
		placeholder = ''
	}: { value?: string; placeholder?: string } = $props();

	let inputEl: HTMLInputElement | undefined = $state();
	let showDropdown = $state(false);
	let highlighted = $state(0);

	function currentToken(): string {
		const idx = value.lastIndexOf(',');
		return value.slice(idx + 1).trim();
	}

	const suggestions = $derived.by(() => {
		const token = currentToken().toLowerCase();
		if (!token) return [];
		return contactsState.contacts
			.filter((c) => (c.name ?? '').toLowerCase().includes(token) || c.email.toLowerCase().includes(token))
			.slice(0, 6);
	});

	function accept(contact: ContactObject) {
		const idx = value.lastIndexOf(',');
		const prefix = idx === -1 ? '' : value.slice(0, idx + 1) + ' ';
		const entry = contact.name ? `${contact.name} <${contact.email}>` : contact.email;
		value = prefix + entry + ', ';
		showDropdown = false;
		highlighted = 0;
		inputEl?.focus();
	}

	function handleKeydown(e: KeyboardEvent) {
		if (!showDropdown || suggestions.length === 0) return;
		if (e.key === 'ArrowDown') {
			e.preventDefault();
			highlighted = (highlighted + 1) % suggestions.length;
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			highlighted = (highlighted - 1 + suggestions.length) % suggestions.length;
		} else if (e.key === 'Enter' || e.key === 'Tab') {
			e.preventDefault();
			accept(suggestions[highlighted]);
		} else if (e.key === 'Escape') {
			showDropdown = false;
		}
	}
</script>

<div class="relative min-w-0 flex-1">
	<input
		bind:this={inputEl}
		type="text"
		{placeholder}
		bind:value
		oninput={() => {
			highlighted = 0;
			showDropdown = true;
		}}
		onkeydown={handleKeydown}
		onfocus={() => (showDropdown = suggestions.length > 0)}
		onblur={() => (showDropdown = false)}
		class="w-full min-w-0 bg-transparent text-[15px] outline-none"
		style="color: var(--text);"
	/>
	{#if showDropdown && suggestions.length > 0}
		<div
			class="absolute top-full left-0 z-20 mt-1 flex flex-col overflow-hidden rounded-[var(--radius-sm)] shadow-lg"
			style="background: var(--surface); border: 1px solid var(--border); min-width: 220px; max-width: 320px;"
		>
			{#each suggestions as suggestion, i (suggestion.id)}
				<button
					type="button"
					onmousedown={(e) => e.preventDefault()}
					onclick={() => accept(suggestion)}
					class="flex flex-col items-start px-3 py-2 text-left text-[13px]"
					style="background: {i === highlighted ? 'var(--surface-hover)' : 'transparent'}; color: var(--text);"
				>
					{#if suggestion.name}
						<span class="font-medium">{suggestion.name}</span>
						<span style="color: var(--text-faint);">{suggestion.email}</span>
					{:else}
						<span>{suggestion.email}</span>
					{/if}
				</button>
			{/each}
		</div>
	{/if}
</div>
