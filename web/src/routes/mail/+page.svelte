<script lang="ts">
	import {
		LockOpenIcon,
		EnvelopeIcon,
		EnvelopeSimpleIcon,
		StarIcon,
		ArchiveIcon,
		TrashIcon,
		MagnifyingGlassIcon,
		XIcon,
		ListIcon,
		DotsThreeVerticalIcon,
		NotePencilIcon
	} from 'phosphor-svelte';
	import { goto } from '$app/navigation';
	import { fade } from 'svelte/transition';
	import { session, lock } from '$lib/session.svelte';
	import {
		loadMailbox,
		setKeyword,
		moveToMailbox,
		destroyEmail,
		KEYWORD_FLAGGED,
		KEYWORD_SEEN,
		KEYWORD_DRAFT,
		DEFAULT_PAGE_SIZE,
		type EmailObject,
		type EmailFilter
	} from '$lib/jmap';
	import { mailNav, refreshMailboxes, toggleDrawer, FLAGGED_VIEW, UNREAD_VIEW } from '$lib/mailNav.svelte';
	import { openDraft, openNewMessage } from '$lib/composeState.svelte';
	import ThemeToggle from '$lib/ThemeToggle.svelte';

	// Focuses the search input when it appears, without the accessibility
	// pitfalls of the `autofocus` attribute (which fires on page load
	// regardless of how the element entered the DOM).
	function focusOnMount(node: HTMLElement) {
		node.focus();
	}

	let emails = $state<EmailObject[]>([]);
	let total = $state(0);
	let loading = $state(true);
	let loadingMore = $state(false);
	let error = $state<string | null>(null);
	let searchOpen = $state(false);
	let searchQuery = $state('');
	let searchTimer: ReturnType<typeof setTimeout> | undefined;
	let menuOpenFor = $state<string | null>(null);

	function toggleMenu(e: MouseEvent, emailId: string) {
		e.preventDefault();
		e.stopPropagation();
		menuOpenFor = menuOpenFor === emailId ? null : emailId;
	}

	function closeMenu() {
		menuOpenFor = null;
	}

	function activeMailboxName(): string {
		if (mailNav.activeViewId === FLAGGED_VIEW) return 'Flagged';
		if (mailNav.activeViewId === UNREAD_VIEW) return 'Unread';
		return mailNav.mailboxes.find((m) => m.id === mailNav.activeViewId)?.name ?? 'Inbox';
	}

	function isFlagged(email: EmailObject): boolean {
		return email.keywords[KEYWORD_FLAGGED] === true;
	}

	function isSeen(email: EmailObject): boolean {
		return email.keywords[KEYWORD_SEEN] === true;
	}

	function isDraft(email: EmailObject): boolean {
		return email.keywords[KEYWORD_DRAFT] === true;
	}

	function addressListLabel(addrs: EmailObject['to']): string {
		return addrs.map((a) => a.name || a.email).join(', ');
	}

	function resumeDraft(e: MouseEvent, email: EmailObject) {
		e.preventDefault();
		openDraft({
			draftId: email.id,
			to: addressListLabel(email.to),
			cc: '',
			subject: email.subject ?? '',
			bodyText: email.bodyText ?? ''
		});
	}

	function toggleUnreadFilter() {
		const inbox = mailNav.mailboxes.find((m) => m.role === 'inbox');
		mailNav.activeViewId = mailNav.activeViewId === UNREAD_VIEW ? (inbox?.id ?? null) : UNREAD_VIEW;
	}

	function currentFilter(view: string, query: string): EmailFilter {
		if (query.trim()) return { text: query.trim() };
		if (view === FLAGGED_VIEW) return { hasKeyword: KEYWORD_FLAGGED };
		if (view === UNREAD_VIEW) return { notHasKeyword: KEYWORD_SEEN };
		return { inMailbox: view };
	}

	// Reload the message list (from the first page) whenever the active
	// view or search query changes, or a compose/archive/delete action
	// completes elsewhere. Search takes priority over the mailbox filter
	// while a query is typed; debounced so it doesn't fire on every
	// keystroke.
	$effect(() => {
		const token = session.token;
		const accountId = session.accountId;
		const view = mailNav.activeViewId;
		const query = searchQuery;
		void mailNav.refreshSignal;
		if (!token || !accountId || view === null) return;

		clearTimeout(searchTimer);
		searchTimer = setTimeout(
			() => {
				loading = true;
				loadMailbox(token, accountId, currentFilter(view, query))
					.then((page) => {
						emails = page.emails;
						total = page.total;
						error = null;
					})
					.catch(() => {
						error = 'Could not load your mail.';
					})
					.finally(() => {
						loading = false;
					});
			},
			query.trim() ? 300 : 0
		);
	});

	async function loadMore() {
		const token = session.token;
		const accountId = session.accountId;
		const view = mailNav.activeViewId;
		if (!token || !accountId || view === null || loadingMore) return;
		loadingMore = true;
		try {
			const page = await loadMailbox(token, accountId, currentFilter(view, searchQuery), emails.length, DEFAULT_PAGE_SIZE);
			emails = [...emails, ...page.emails];
			total = page.total;
		} catch {
			error = 'Could not load more mail.';
		} finally {
			loadingMore = false;
		}
	}

	async function handleLock() {
		await lock();
		await goto('/');
	}

	async function toggleFlag(e: MouseEvent, email: EmailObject) {
		e.preventDefault();
		e.stopPropagation();
		const token = session.token;
		const accountId = session.accountId;
		if (!token || !accountId) return;
		const next = !isFlagged(email);
		email.keywords = { ...email.keywords, [KEYWORD_FLAGGED]: next };
		try {
			await setKeyword(token, accountId, email.id, KEYWORD_FLAGGED, next);
		} catch {
			email.keywords = { ...email.keywords, [KEYWORD_FLAGGED]: !next };
		}
	}

	async function archiveEmail(e: MouseEvent, email: EmailObject) {
		e.preventDefault();
		e.stopPropagation();
		closeMenu();
		const token = session.token;
		const accountId = session.accountId;
		const archive = mailNav.mailboxes.find((m) => m.role === 'archive');
		if (!token || !accountId || !archive) return;
		emails = emails.filter((m) => m.id !== email.id);
		try {
			await moveToMailbox(token, accountId, email.id, archive.id);
			await refreshMailboxes();
		} catch {
			emails = [...emails, email];
		}
	}

	async function deleteEmail(e: MouseEvent, email: EmailObject) {
		e.preventDefault();
		e.stopPropagation();
		closeMenu();
		const token = session.token;
		const accountId = session.accountId;
		if (!token || !accountId) return;
		emails = emails.filter((m) => m.id !== email.id);
		try {
			await destroyEmail(token, accountId, email.id);
			await refreshMailboxes();
		} catch {
			emails = [...emails, email];
		}
	}

	function senderLabel(email: EmailObject) {
		const from = email.from[0];
		if (!from) return '(unknown sender)';
		return from.name || from.email;
	}

	function timeLabel(iso: string) {
		const date = new Date(iso);
		return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
	}
</script>

<div class="flex min-h-screen flex-col">
	<header
		class="flex items-center justify-between px-4 py-4"
		style="border-bottom: 1px solid var(--border);"
	>
		{#if searchOpen}
			<div class="flex flex-1 items-center gap-2">
				<MagnifyingGlassIcon size={18} style="color: var(--text-faint); flex-shrink: 0;" />
				<input
					type="text"
					inputmode="search"
					placeholder="Search mail…"
					bind:value={searchQuery}
					use:focusOnMount
					class="min-w-0 flex-1 bg-transparent text-[15px] outline-none"
					style="color: var(--text);"
				/>
				<button
					onclick={() => {
						searchOpen = false;
						searchQuery = '';
					}}
					aria-label="Close search"
					class="flex h-11 w-11 shrink-0 items-center justify-center rounded-full transition-colors hover:bg-[var(--surface-hover)]"
					style="color: var(--text-muted);"
				>
					<XIcon size={18} />
				</button>
			</div>
		{:else}
			<div class="flex min-w-0 items-center gap-1">
				<button
					onclick={toggleDrawer}
					aria-label="Open menu"
					class="flex h-11 w-11 shrink-0 items-center justify-center rounded-full transition-colors hover:bg-[var(--surface-hover)] sm:hidden"
					style="color: var(--text-muted);"
				>
					<ListIcon size={20} />
				</button>
				<div class="min-w-0">
					<h1 class="truncate text-lg font-semibold" style="color: var(--text);">{activeMailboxName()}</h1>
					<p class="truncate text-xs" style="color: var(--text-faint);">{session.address}</p>
				</div>
			</div>
			<div class="flex shrink-0 items-center">
				<button
					onclick={() => (searchOpen = true)}
					aria-label="Search mail"
					class="flex h-11 w-11 items-center justify-center rounded-full transition-colors hover:bg-[var(--surface-hover)]"
					style="color: var(--text-muted);"
				>
					<MagnifyingGlassIcon size={20} />
				</button>
				<button
					onclick={toggleUnreadFilter}
					aria-label={mailNav.activeViewId === UNREAD_VIEW ? 'Show all mail' : 'Show unread only'}
					aria-pressed={mailNav.activeViewId === UNREAD_VIEW}
					class="flex h-11 w-11 items-center justify-center rounded-full transition-colors hover:bg-[var(--surface-hover)]"
					style="color: {mailNav.activeViewId === UNREAD_VIEW ? 'var(--accent)' : 'var(--text-muted)'};"
				>
					<EnvelopeSimpleIcon size={20} weight={mailNav.activeViewId === UNREAD_VIEW ? 'fill' : 'regular'} />
				</button>
				<ThemeToggle />
				<button
					onclick={handleLock}
					aria-label="Lock mailbox"
					class="flex h-11 w-11 items-center justify-center rounded-full transition-colors hover:bg-[var(--surface-hover)]"
					style="color: var(--text-muted);"
				>
					<LockOpenIcon size={20} />
				</button>
			</div>
		{/if}
	</header>

	<main class="flex-1">
		{#if loading}
			<div class="flex animate-pulse flex-col gap-2 p-4">
				{#each Array(5) as _}
					<div class="h-16 rounded-[var(--radius)]" style="background: var(--surface-sunk);"></div>
				{/each}
			</div>
		{:else if error}
			<p class="p-6 text-center text-sm" style="color: var(--danger);">{error}</p>
		{:else if emails.length === 0}
			<div class="flex flex-col items-center gap-4 p-16 text-center" in:fade={{ duration: 200 }}>
				<div
					class="flex h-16 w-16 items-center justify-center rounded-full"
					style="background: var(--surface-sunk);"
				>
					<EnvelopeIcon size={28} style="color: var(--text-faint);" />
				</div>
				<p class="text-sm" style="color: var(--text-faint);">
					{searchQuery.trim() ? 'No matches.' : 'Nothing here yet.'}
				</p>
			</div>
		{:else}
			<ul>
				{#each emails as email (email.id)}
					<li class="relative flex items-start" style="border-bottom: 1px solid var(--border);">
						<a
							href={`/mail/${email.id}`}
							onclick={isDraft(email) ? (e) => resumeDraft(e, email) : undefined}
							class="block min-w-0 flex-1 py-3.5 pr-2 pl-4 transition-colors hover:bg-[var(--surface-hover)]"
							style="color: var(--text);"
						>
							<div class="mb-0.5 flex items-center gap-2">
								{#if !isSeen(email)}
									<span
										class="h-2 w-2 shrink-0 rounded-full"
										style="background: var(--accent);"
										aria-hidden="true"
									></span>
								{/if}
								<div class="flex min-w-0 flex-1 items-baseline justify-between gap-2">
									<span class="truncate text-[15px]" class:font-semibold={!isSeen(email)} class:font-medium={isSeen(email)}>
										{isDraft(email) ? `To ${addressListLabel(email.to) || '(no recipient)'}` : senderLabel(email)}
									</span>
									<span class="shrink-0 text-xs tabular-nums" style="color: var(--text-faint);"
										>{timeLabel(email.receivedAt)}</span
									>
								</div>
							</div>
							<div class="mb-0.5 flex items-center gap-1.5 truncate pl-4 text-[15px]" style="color: var(--text);">
								{#if isDraft(email)}
									<span class="shrink-0 text-xs font-medium" style="color: var(--danger);">Draft</span>
								{/if}
								<span class="truncate" class:font-semibold={!isSeen(email)}>{email.subject || '(no subject)'}</span>
							</div>
							<div class="truncate pl-4 text-sm" style="color: var(--text-muted);">
								{email.preview}
							</div>
						</a>
						<div class="flex shrink-0 items-center pr-1">
							<button
								onclick={(e) => toggleFlag(e, email)}
								aria-label={isFlagged(email) ? 'Unflag' : 'Flag'}
								class="flex h-11 w-11 items-center justify-center rounded-full transition-colors hover:bg-[var(--surface-hover)]"
								style="color: {isFlagged(email) ? 'var(--accent)' : 'var(--text-faint)'};"
							>
								<StarIcon size={17} weight={isFlagged(email) ? 'fill' : 'regular'} />
							</button>
							<button
								onclick={(e) => toggleMenu(e, email.id)}
								aria-label="More actions"
								aria-expanded={menuOpenFor === email.id}
								class="flex h-11 w-11 items-center justify-center rounded-full transition-colors hover:bg-[var(--surface-hover)]"
								style="color: var(--text-faint);"
							>
								<DotsThreeVerticalIcon size={18} weight="bold" />
							</button>
						</div>

						{#if menuOpenFor === email.id}
							<button
								aria-label="Close menu"
								class="fixed inset-0 z-10 cursor-default"
								onclick={closeMenu}
							></button>
							<div
								class="absolute top-11 right-2 z-20 flex flex-col overflow-hidden rounded-[var(--radius-sm)] shadow-lg"
								style="background: var(--surface); border: 1px solid var(--border); min-width: 160px;"
							>
								<button
									onclick={(e) => archiveEmail(e, email)}
									class="flex items-center gap-2.5 px-4 py-3 text-left text-[14px] transition-colors hover:bg-[var(--surface-hover)]"
									style="color: var(--text);"
								>
									<ArchiveIcon size={17} />
									Archive
								</button>
								<button
									onclick={(e) => deleteEmail(e, email)}
									class="flex items-center gap-2.5 px-4 py-3 text-left text-[14px] transition-colors hover:bg-[color-mix(in_oklch,var(--danger)_15%,transparent)]"
									style="color: var(--danger);"
								>
									<TrashIcon size={17} />
									Delete
								</button>
							</div>
						{/if}
					</li>
				{/each}
			</ul>
			{#if emails.length < total}
				<div class="flex justify-center p-4">
					<button
						onclick={loadMore}
						disabled={loadingMore}
						class="rounded-full px-4 py-2 text-[13px] font-medium transition-colors hover:bg-[var(--surface-hover)] disabled:opacity-60"
						style="color: var(--text-muted); background: var(--surface-sunk);"
					>
						{loadingMore ? 'Loading…' : `Load more (${total - emails.length} left)`}
					</button>
				</div>
			{/if}
		{/if}
	</main>

	<button
		onclick={openNewMessage}
		aria-label="New message"
		class="fixed right-5 bottom-6 flex h-14 w-14 items-center justify-center rounded-full text-white shadow-lg transition-opacity hover:opacity-90 sm:hidden"
		style="background: var(--accent);"
	>
		<NotePencilIcon size={22} weight="bold" />
	</button>
</div>
