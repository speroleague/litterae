// Shared contacts cache -- loaded once per session and re-fetched on
// server push, the same way `mailNav.svelte.ts` shares mailbox state.
// The account's whole address book is expected to be small (personal/
// small-tenant server), so it's kept in full client-side rather than
// re-querying the server per keystroke: both the Compose typeahead and
// the message-view "is this a contact?" lookup read this cache directly.

import { getContacts, type ContactObject } from './jmap';
import { session } from './session.svelte';

class ContactsState {
	contacts = $state<ContactObject[]>([]);
	/** Keyed by lowercased email for O(1) "is this address a contact?"
	 * lookups from the message view. */
	byEmail = $derived(new Map(this.contacts.map((c) => [c.email.toLowerCase(), c])));
}

export const contactsState = new ContactsState();

export async function loadContacts() {
	const token = session.token;
	const accountId = session.accountId;
	if (!token || !accountId) return;
	contactsState.contacts = await getContacts(token, accountId);
}
