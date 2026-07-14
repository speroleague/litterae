<script lang="ts">
	import { fade, fly } from 'svelte/transition';
	import { XIcon, PaperPlaneTiltIcon } from 'phosphor-svelte';
	import { session } from '$lib/session.svelte';
	import { saveDraft, updateDraft, submitEmail, sendNewEmail, type ComposeInput } from '$lib/jmap';
	import { composeState, closeCompose, parseAddressList } from '$lib/composeState.svelte';
	import { bumpRefresh, refreshMailboxes } from '$lib/mailNav.svelte';

	let ccOpen = $state(false);
	let sending = $state(false);
	let savingDraft = $state(false);
	let error = $state<string | null>(null);

	$effect(() => {
		if (composeState.open) {
			ccOpen = composeState.cc.trim().length > 0;
			error = null;
		}
	});

	function buildInput(): ComposeInput {
		return {
			to: parseAddressList(composeState.to),
			cc: parseAddressList(composeState.cc),
			subject: composeState.subject.trim() || undefined,
			bodyText: composeState.bodyText,
			inReplyTo: composeState.draftId ? undefined : (composeState.inReplyTo ?? undefined)
		};
	}

	async function handleSaveDraft() {
		const token = session.token;
		const accountId = session.accountId;
		if (!token || !accountId || savingDraft || sending) return;
		error = null;
		savingDraft = true;
		try {
			const input = buildInput();
			const draft = composeState.draftId
				? await updateDraft(token, accountId, composeState.draftId, input)
				: await saveDraft(token, accountId, input);
			composeState.draftId = draft.id;
			bumpRefresh();
			await refreshMailboxes();
			closeCompose();
		} catch {
			error = 'Could not save this draft.';
		} finally {
			savingDraft = false;
		}
	}

	async function handleSend() {
		const token = session.token;
		const accountId = session.accountId;
		if (!token || !accountId || sending || savingDraft) return;
		if (parseAddressList(composeState.to).length === 0) {
			error = 'Add at least one recipient.';
			return;
		}
		error = null;
		sending = true;
		try {
			const input = buildInput();
			const rcptTo = [...input.to, ...(input.cc ?? [])].map((a) => a.email);
			if (composeState.draftId) {
				const draft = await updateDraft(token, accountId, composeState.draftId, input);
				await submitEmail(token, accountId, draft.id, rcptTo);
			} else {
				await sendNewEmail(token, accountId, input);
			}
			bumpRefresh();
			await refreshMailboxes();
			closeCompose();
		} catch {
			error = 'Could not send this message.';
		} finally {
			sending = false;
		}
	}
</script>

{#if composeState.open}
	<div class="fixed inset-0 z-30 flex flex-col justify-end sm:items-center sm:justify-center">
		<button
			aria-label="Close compose"
			class="fixed inset-0 cursor-default"
			style="background: rgba(0,0,0,0.4);"
			onclick={closeCompose}
			transition:fade={{ duration: 150 }}
		></button>
		<div
			class="relative z-10 flex w-full flex-col sm:max-h-[85vh] sm:w-full sm:max-w-lg sm:rounded-[var(--radius)]"
			style="background: var(--surface); border-top: 1px solid var(--border); max-height: 90vh;"
			transition:fly={{ y: 24, duration: 200 }}
		>
			<header
				class="flex items-center justify-between px-4 py-3"
				style="border-bottom: 1px solid var(--border);"
			>
				<h2 class="text-[15px] font-semibold" style="color: var(--text);">
					{composeState.inReplyTo ? 'Reply' : 'New Message'}
				</h2>
				<button
					onclick={closeCompose}
					aria-label="Close"
					class="flex h-9 w-9 items-center justify-center rounded-full"
					style="color: var(--text-muted);"
				>
					<XIcon size={18} />
				</button>
			</header>

			<div class="flex flex-1 flex-col gap-0 overflow-y-auto">
				<div class="flex items-center gap-2 px-4 py-2.5 text-sm" style="border-bottom: 1px solid var(--border);">
					<span style="color: var(--text-faint);">From</span>
					<span style="color: var(--text);">{session.address}</span>
				</div>
				<div class="flex items-center gap-2 px-4 py-2.5" style="border-bottom: 1px solid var(--border);">
					<span class="w-8 shrink-0 text-sm" style="color: var(--text-faint);">To</span>
					<input
						type="text"
						placeholder="alice@example.com"
						bind:value={composeState.to}
						class="min-w-0 flex-1 bg-transparent text-[15px] outline-none"
						style="color: var(--text);"
					/>
					{#if !ccOpen}
						<button
							onclick={() => (ccOpen = true)}
							class="shrink-0 text-xs font-medium"
							style="color: var(--text-faint);"
						>
							Cc
						</button>
					{/if}
				</div>
				{#if ccOpen}
					<div class="flex items-center gap-2 px-4 py-2.5" style="border-bottom: 1px solid var(--border);">
						<span class="w-8 shrink-0 text-sm" style="color: var(--text-faint);">Cc</span>
						<input
							type="text"
							placeholder="cc@example.com"
							bind:value={composeState.cc}
							class="min-w-0 flex-1 bg-transparent text-[15px] outline-none"
							style="color: var(--text);"
						/>
					</div>
				{/if}
				<div class="px-4 py-2.5" style="border-bottom: 1px solid var(--border);">
					<input
						type="text"
						placeholder="Subject"
						bind:value={composeState.subject}
						class="w-full bg-transparent text-[15px] outline-none"
						style="color: var(--text);"
					/>
				</div>
				<textarea
					placeholder="Write your message…"
					bind:value={composeState.bodyText}
					class="min-h-[320px] flex-1 resize-none bg-transparent px-4 py-3 text-[15px] leading-relaxed outline-none"
					style="color: var(--text);"
				></textarea>
			</div>

			{#if error}
				<p class="px-4 pb-1 text-sm" style="color: var(--danger);">{error}</p>
			{/if}

			<footer class="flex items-center justify-between gap-2 px-4 py-3" style="border-top: 1px solid var(--border);">
				<button
					onclick={handleSaveDraft}
					disabled={savingDraft || sending}
					class="rounded-[var(--radius-sm)] px-3.5 py-2 text-[14px] font-medium transition-opacity disabled:opacity-50"
					style="color: var(--text-muted); background: var(--surface-sunk);"
				>
					{savingDraft ? 'Saving…' : 'Save Draft'}
				</button>
				<button
					onclick={handleSend}
					disabled={sending || savingDraft}
					class="flex items-center gap-1.5 rounded-[var(--radius-sm)] px-4 py-2 text-[14px] font-medium text-white transition-opacity disabled:opacity-60"
					style="background: var(--accent);"
				>
					<PaperPlaneTiltIcon size={16} weight="fill" />
					{sending ? 'Sending…' : 'Send'}
				</button>
			</footer>
		</div>
	</div>
{/if}
