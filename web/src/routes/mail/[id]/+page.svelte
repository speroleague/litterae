<script lang="ts">
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { CaretLeftIcon, StarIcon, ArchiveIcon, TrashIcon, ArrowBendUpLeftIcon, ArrowElbowDownRightIcon } from 'phosphor-svelte';
	import { session } from '$lib/session.svelte';
	import {
		getEmails,
		setKeyword,
		moveToMailbox,
		destroyEmail,
		getThreadEmailIds,
		KEYWORD_FLAGGED,
		KEYWORD_SEEN,
		KEYWORD_DRAFT,
		type EmailObject
	} from '$lib/jmap';
	import { mailNav, refreshMailboxes, bumpRefresh } from '$lib/mailNav.svelte';
	import { openReply, openDraft } from '$lib/composeState.svelte';
	import MailBodyFrame from '$lib/MailBodyFrame.svelte';

	let email = $state<EmailObject | null>(null);
	let threadEmails = $state<EmailObject[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);
	let busy = $state(false);

	$effect(() => {
		const token = session.token;
		const accountId = session.accountId;
		const id = page.params.id;
		void mailNav.refreshSignal;
		if (!token || !accountId || !id) return;
		loading = true;
		getEmails(token, accountId, [id])
			.then(async (emails) => {
				email = emails[0] ?? null;
				threadEmails = [];
				if (email && isDraft(email)) {
					openDraft({
						draftId: email.id,
						to: addressListLabel(email.to),
						cc: '',
						subject: email.subject ?? '',
						bodyText: email.bodyText ?? ''
					});
					await goto('/mail');
					return;
				}
				if (email) {
					const siblingIds = (await getThreadEmailIds(token, accountId, email.threadId)).filter(
						(sid) => sid !== email!.id
					);
					if (siblingIds.length > 0) {
						threadEmails = await getEmails(token, accountId, siblingIds);
					}
					if (email.keywords[KEYWORD_SEEN] !== true) {
						email.keywords = { ...email.keywords, [KEYWORD_SEEN]: true };
						try {
							await setKeyword(token, accountId, email.id, KEYWORD_SEEN, true);
							bumpRefresh();
						} catch {
							// Not worth surfacing to the user -- the message still
							// opened and displayed correctly, this only affects the
							// unread badge/filter staying slightly stale.
						}
					}
				}
				error = null;
			})
			.catch(() => {
				error = 'Could not load this message.';
			})
			.finally(() => {
				loading = false;
			});
	});

	function isDraft(m: EmailObject): boolean {
		return m.keywords[KEYWORD_DRAFT] === true;
	}

	function addressListLabel(addrs: EmailObject['to']): string {
		return addrs.map((a) => a.name || a.email).join(', ');
	}

	// Where in the thread this message belongs: which message (if any) it
	// was a reply to. `threadEmails` only holds siblings, so this is a
	// lookup, not a fetch.
	let parentEmail = $derived(
		email?.inReplyToMessageId
			? (threadEmails.find((m) => m.messageId === email!.inReplyToMessageId) ?? null)
			: null
	);

	function openThreadItem(e: MouseEvent, m: EmailObject) {
		if (isDraft(m)) {
			e.preventDefault();
			openDraft({
				draftId: m.id,
				to: addressListLabel(m.to),
				cc: '',
				subject: m.subject ?? '',
				bodyText: m.bodyText ?? ''
			});
		}
	}

	function handleReply() {
		if (!email) return;
		const replyTo = email.from[0]?.email ?? '';
		openReply({ to: replyTo, subject: email.subject ?? '', inReplyTo: email.id });
	}

	function isFlagged(): boolean {
		return email?.keywords[KEYWORD_FLAGGED] === true;
	}

	async function toggleFlag() {
		const token = session.token;
		const accountId = session.accountId;
		if (!token || !accountId || !email) return;
		const next = !isFlagged();
		email.keywords = { ...email.keywords, [KEYWORD_FLAGGED]: next };
		try {
			await setKeyword(token, accountId, email.id, KEYWORD_FLAGGED, next);
		} catch {
			if (email) email.keywords = { ...email.keywords, [KEYWORD_FLAGGED]: !next };
		}
	}

	async function archiveEmail() {
		const token = session.token;
		const accountId = session.accountId;
		const archive = mailNav.mailboxes.find((m) => m.role === 'archive');
		if (!token || !accountId || !email || !archive || busy) return;
		busy = true;
		try {
			await moveToMailbox(token, accountId, email.id, archive.id);
			await refreshMailboxes();
			await goto('/mail');
		} finally {
			busy = false;
		}
	}

	async function deleteEmail() {
		const token = session.token;
		const accountId = session.accountId;
		if (!token || !accountId || !email || busy) return;
		busy = true;
		try {
			await destroyEmail(token, accountId, email.id);
			await refreshMailboxes();
			await goto('/mail');
		} finally {
			busy = false;
		}
	}

	function fullDate(iso: string) {
		return new Date(iso).toLocaleString(undefined, {
			dateStyle: 'medium',
			timeStyle: 'short'
		});
	}

	function addressLabel(addr: { name: string | null; email: string }) {
		return addr.name ? `${addr.name} <${addr.email}>` : addr.email;
	}
</script>

<div class="mx-auto flex min-h-screen max-w-4xl flex-col">
	<header
		class="flex items-center justify-between gap-2 px-2 py-3"
		style="border-bottom: 1px solid var(--border);"
	>
		<div class="flex items-center gap-2">
			<button
				onclick={() => goto('/mail')}
				aria-label="Back"
				class="flex h-11 w-11 items-center justify-center rounded-full transition-colors hover:bg-[var(--surface-hover)]"
				style="color: var(--text-muted);"
			>
				<CaretLeftIcon size={20} />
			</button>
			<span class="text-sm" style="color: var(--text-muted);">Back</span>
		</div>
		{#if email}
			<div class="flex items-center gap-1">
				<button
					onclick={handleReply}
					aria-label="Reply"
					class="flex h-11 w-11 items-center justify-center rounded-full transition-colors hover:bg-[var(--surface-hover)]"
					style="color: var(--text-muted);"
				>
					<ArrowBendUpLeftIcon size={19} />
				</button>
				<button
					onclick={toggleFlag}
					aria-label={isFlagged() ? 'Unflag' : 'Flag'}
					class="flex h-11 w-11 items-center justify-center rounded-full transition-colors hover:bg-[var(--surface-hover)]"
					style="color: {isFlagged() ? 'var(--accent)' : 'var(--text-muted)'};"
				>
					<StarIcon size={19} weight={isFlagged() ? 'fill' : 'regular'} />
				</button>
				<button
					onclick={archiveEmail}
					disabled={busy}
					aria-label="Archive"
					class="flex h-11 w-11 items-center justify-center rounded-full transition-colors hover:bg-[var(--surface-hover)] disabled:opacity-50"
					style="color: var(--text-muted);"
				>
					<ArchiveIcon size={19} />
				</button>
				<button
					onclick={deleteEmail}
					disabled={busy}
					aria-label="Delete"
					class="flex h-11 w-11 items-center justify-center rounded-full transition-colors hover:bg-[color-mix(in_oklch,var(--danger)_15%,transparent)] hover:text-[var(--danger)] disabled:opacity-50"
					style="color: var(--text-muted);"
				>
					<TrashIcon size={19} />
				</button>
			</div>
		{/if}
	</header>

	<main class="flex-1 px-5 py-5">
		{#if loading}
			<div class="flex flex-col gap-3">
				<div class="h-6 w-2/3 rounded" style="background: var(--surface-sunk);"></div>
				<div class="h-4 w-1/3 rounded" style="background: var(--surface-sunk);"></div>
				<div class="mt-4 h-32 rounded-[var(--radius)]" style="background: var(--surface-sunk);"></div>
			</div>
		{:else if error}
			<p class="text-sm" style="color: var(--danger);">{error}</p>
		{:else if email}
			<h1 class="mb-3 text-xl font-semibold" style="color: var(--text); max-width: 90ch;">
				{email.subject || '(no subject)'}
			</h1>
			<div class="mb-6 flex flex-col gap-0.5 text-sm">
				<div style="color: var(--text);">
					{#each email.from as addr}
						<span>{addressLabel(addr)}</span>
					{/each}
				</div>
				<div style="color: var(--text-faint);">
					to {email.to.map(addressLabel).join(', ')} · {fullDate(email.receivedAt)}
				</div>
			</div>
			{#if parentEmail}
				<a
					href={`/mail/${parentEmail.id}`}
					class="mb-3 flex items-center gap-1.5 text-sm transition-colors hover:underline"
					style="color: var(--text-faint); max-width: 90ch;"
				>
					<ArrowElbowDownRightIcon size={14} />
					<span class="truncate">
						In reply to {parentEmail.from[0]?.name || parentEmail.from[0]?.email || '(unknown sender)'} ·
						{fullDate(parentEmail.receivedAt)}
					</span>
				</a>
			{/if}
			{#if email.bodyHtml}
				<MailBodyFrame bodyHtml={email.bodyHtml} blockedImageCount={email.blockedImageCount ?? 0} />
			{:else}
				<div
					class="overflow-x-auto rounded-[var(--radius)] p-4 text-[16px] leading-relaxed whitespace-pre-wrap"
					style="background: var(--surface); border: 1px solid var(--border); max-width: 90ch; color: var(--text); overflow-wrap: anywhere;"
				>
					{email.bodyText || '(no text body)'}
				</div>
			{/if}

			{#if threadEmails.length > 0}
				<div class="mt-6" style="max-width: 90ch;">
					<h2 class="mb-2 text-xs font-medium tracking-wide uppercase" style="color: var(--text-faint);">
						Also in this thread
					</h2>
					<ul class="flex flex-col gap-2">
						{#each threadEmails as m (m.id)}
							<li>
								<a
									href={`/mail/${m.id}`}
									onclick={(e) => openThreadItem(e, m)}
									class="block rounded-[var(--radius)] border border-[var(--border)] bg-[var(--surface)] p-3 transition-colors hover:bg-[var(--surface-hover)]"
								>
									<div class="mb-0.5 flex items-center justify-between gap-2">
										<span class="flex items-center gap-1.5 truncate text-sm font-medium" style="color: var(--text);">
											{#if isDraft(m)}
												<span class="shrink-0 text-xs font-medium" style="color: var(--danger);">Draft</span>
											{/if}
											{isDraft(m) ? `To ${addressListLabel(m.to) || '(no recipient)'}` : m.from[0]?.email}
										</span>
										<span class="shrink-0 text-xs" style="color: var(--text-faint);">{fullDate(m.receivedAt)}</span>
									</div>
									<p class="truncate text-sm" style="color: var(--text-muted);">{m.preview}</p>
								</a>
							</li>
						{/each}
					</ul>
				</div>
			{/if}
		{/if}
	</main>
</div>
