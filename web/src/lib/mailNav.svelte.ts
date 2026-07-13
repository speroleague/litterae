// Shared mailbox nav state -- the sidebar, the mail list, and the message
// view all read/drive this instead of each fetching/tracking their own
// copy, which was the root of two bugs: (1) the sidebar's per-mailbox
// counts were fetched once at mount and never refreshed after a send/
// archive/delete elsewhere, so they drifted from the real list; (2) the
// email list only reloaded on its own actions, not on changes made from a
// different view (e.g. sending a reply while looking at the thread).

import { goto } from '$app/navigation';

import { getMailboxes, type MailboxObject } from './jmap';
import { session } from './session.svelte';

// Flagged and Unread are virtual views (a keyword filter, not a real
// mailbox), so neither is in the Mailbox/get list -- handled specially
// wherever a mailbox id would normally go. Unread spans every real
// mailbox at once (Inbox+Archive+Sent+...), same as Flagged already does.
export const FLAGGED_VIEW = '__flagged__';
export const UNREAD_VIEW = '__unread__';

class MailNavState {
	mailboxes = $state<MailboxObject[]>([]);
	activeViewId = $state<string | null>(null);
	drawerOpen = $state(false);
	/** Bumped after any action that changes mailbox contents (send, save
	 * draft, archive, delete) -- both the active email list and the
	 * sidebar's per-mailbox counts watch this so neither goes stale after
	 * a mutation made from elsewhere. */
	refreshSignal = $state(0);
}

export const mailNav = new MailNavState();

/** Refetches the mailbox list (and its counts). Call after unlock, and
 * after anything that moves/creates/destroys a message. */
export async function refreshMailboxes() {
	const token = session.token;
	const accountId = session.accountId;
	if (!token || !accountId) return;
	const list = await getMailboxes(token, accountId);
	mailNav.mailboxes = list;
	if (mailNav.activeViewId === null) {
		const inbox = list.find((m) => m.role === 'inbox');
		mailNav.activeViewId = inbox?.id ?? list[0]?.id ?? null;
	}
}

export function selectView(id: string) {
	mailNav.activeViewId = id;
	mailNav.drawerOpen = false;
	goto('/mail');
}

export function toggleDrawer() {
	mailNav.drawerOpen = !mailNav.drawerOpen;
}

export function closeDrawer() {
	mailNav.drawerOpen = false;
}

/** Tells the active list (and the sidebar counts, via a refreshMailboxes()
 * call alongside this at each call site) to reload. */
export function bumpRefresh() {
	mailNav.refreshSignal++;
}
