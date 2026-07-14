<script lang="ts">
	import { goto } from '$app/navigation';
	import { fade, fly } from 'svelte/transition';
	import { XIcon } from 'phosphor-svelte';
	import { session } from '$lib/session.svelte';
	import { subscribeToChanges, getIdentity } from '$lib/jmap';
	import { mailNav, refreshMailboxes, bumpRefresh, closeDrawer } from '$lib/mailNav.svelte';
	import { setSignature } from '$lib/composeState.svelte';
	import MailSidebar from '$lib/MailSidebar.svelte';
	import Compose from '$lib/Compose.svelte';

	let { children } = $props();

	$effect(() => {
		if (!session.isUnlocked) {
			goto('/');
		}
	});

	$effect(() => {
		if (session.isUnlocked) {
			refreshMailboxes();
		}
	});

	$effect(() => {
		const token = session.token;
		const accountId = session.accountId;
		if (!token || !accountId) return;
		getIdentity(token, accountId)
			.then((identity) => setSignature(identity?.textSignature ?? ''))
			.catch(() => {});
	});

	// Live updates (RFC 8620 §7.3 push): re-fetch on any server-side change
	// to this account -- new mail arriving, a send/archive/delete from
	// another tab or device -- instead of only ever refreshing after the
	// user's own actions here.
	$effect(() => {
		const token = session.token;
		if (!token) return;
		const unsubscribe = subscribeToChanges(token, () => {
			refreshMailboxes();
			bumpRefresh();
		});
		return unsubscribe;
	});
</script>

{#if session.isUnlocked}
	<div class="mx-auto flex min-h-screen max-w-6xl">
		<aside class="hidden w-60 shrink-0 sm:block" style="border-right: 1px solid var(--border);">
			<MailSidebar />
		</aside>

		{#if mailNav.drawerOpen}
			<button
				aria-label="Close menu"
				class="fixed inset-0 z-30 cursor-default sm:hidden"
				style="background: rgba(0,0,0,0.3);"
				onclick={closeDrawer}
				transition:fade={{ duration: 150 }}
			></button>
			<aside
				class="fixed inset-y-0 left-0 z-40 flex w-64 max-w-[80vw] flex-col sm:hidden"
				style="background: var(--surface); border-right: 1px solid var(--border);"
				transition:fly={{ x: -256, duration: 200 }}
			>
				<div class="flex items-center justify-between px-3 py-3" style="border-bottom: 1px solid var(--border);">
					<span class="text-sm font-semibold" style="color: var(--text);">Mailboxes</span>
					<button
						onclick={closeDrawer}
						aria-label="Close menu"
						class="flex h-9 w-9 items-center justify-center rounded-full"
						style="color: var(--text-muted);"
					>
						<XIcon size={18} />
					</button>
				</div>
				<div class="min-h-0 flex-1">
					<MailSidebar />
				</div>
			</aside>
		{/if}

		<div class="min-w-0 flex-1">
			{@render children()}
		</div>
	</div>
	<Compose />
{/if}
