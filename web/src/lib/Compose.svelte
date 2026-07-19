<script lang="ts">
	import { fade, fly } from 'svelte/transition';
	import { XIcon, PaperPlaneTiltIcon, PaperclipIcon, FileIcon } from 'phosphor-svelte';
	import { session } from '$lib/session.svelte';
	import { saveDraft, updateDraft, submitEmail, sendNewEmail, uploadAttachment, formatFileSize, JmapError, type ComposeInput } from '$lib/jmap';
	import { composeState, closeCompose, parseAddressList, addAttachment, removeAttachment } from '$lib/composeState.svelte';
	import { bumpRefresh, refreshMailboxes } from '$lib/mailNav.svelte';
	import RichTextEditor from './RichTextEditor.svelte';

	let ccOpen = $state(false);
	let sending = $state(false);
	let savingDraft = $state(false);
	let error = $state<string | null>(null);
	let uploadingCount = $state(0);
	let fileInput: HTMLInputElement | undefined = $state();

	$effect(() => {
		if (composeState.open) {
			ccOpen = composeState.cc.trim().length > 0;
			error = null;
		}
	});

	async function handleFilesPicked(e: Event) {
		const files = (e.target as HTMLInputElement).files;
		if (!files || files.length === 0) return;
		const token = session.token;
		if (!token) return;
		for (const file of Array.from(files)) {
			uploadingCount++;
			try {
				const uploaded = await uploadAttachment(token, file);
				addAttachment({ blobId: uploaded.blobId, name: file.name, size: uploaded.size });
			} catch (err) {
				error = err instanceof JmapError ? 'One or more files could not be attached (rejected or too large).' : 'Could not attach file.';
			} finally {
				uploadingCount--;
			}
		}
		if (fileInput) fileInput.value = '';
	}

	function buildInput(): ComposeInput {
		return {
			to: parseAddressList(composeState.to),
			cc: parseAddressList(composeState.cc),
			subject: composeState.subject.trim() || undefined,
			bodyHtml: composeState.bodyHtml,
			inReplyTo: composeState.draftId ? undefined : (composeState.inReplyTo ?? undefined),
			attachmentBlobIds: composeState.attachments.map((a) => a.blobId)
		};
	}

	async function handleSaveDraft() {
		const token = session.token;
		const accountId = session.accountId;
		if (!token || !accountId || savingDraft || sending || uploadingCount > 0) return;
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
		if (!token || !accountId || sending || savingDraft || uploadingCount > 0) return;
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
			class="relative z-10 flex w-full flex-col sm:max-h-[88vh] sm:w-full sm:max-w-2xl sm:rounded-[var(--radius)]"
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
				<RichTextEditor bind:html={composeState.bodyHtml} />

				{#if composeState.attachments.length > 0 || uploadingCount > 0}
					<div class="flex flex-wrap gap-2 px-4 pb-3">
						{#each composeState.attachments as attachment (attachment.blobId)}
							<span
								class="flex items-center gap-1.5 rounded-full py-1 pr-1.5 pl-2.5 text-[13px]"
								style="background: var(--surface-sunk); color: var(--text-muted);"
							>
								<FileIcon size={14} />
								<span class="max-w-[160px] truncate">{attachment.name}</span>
								<span style="color: var(--text-faint);">{formatFileSize(attachment.size)}</span>
								<button
									onclick={() => removeAttachment(attachment.blobId)}
									aria-label={`Remove ${attachment.name}`}
									class="flex h-5 w-5 items-center justify-center rounded-full"
								>
									<XIcon size={12} />
								</button>
							</span>
						{/each}
						{#each Array(uploadingCount) as _}
							<span
								class="flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[13px]"
								style="background: var(--surface-sunk); color: var(--text-faint);"
							>
								Uploading…
							</span>
						{/each}
					</div>
				{/if}
			</div>

			{#if error}
				<p class="px-4 pb-1 text-sm" style="color: var(--danger);">{error}</p>
			{/if}

			<footer class="flex items-center justify-between gap-2 px-4 py-3" style="border-top: 1px solid var(--border);">
				<div class="flex items-center gap-2">
					<input
						bind:this={fileInput}
						type="file"
						multiple
						class="hidden"
						onchange={handleFilesPicked}
					/>
					<button
						onclick={() => fileInput?.click()}
						aria-label="Attach files"
						class="flex h-9 w-9 items-center justify-center rounded-full"
						style="color: var(--text-muted); background: var(--surface-sunk);"
					>
						<PaperclipIcon size={17} />
					</button>
					<button
						onclick={handleSaveDraft}
						disabled={savingDraft || sending || uploadingCount > 0}
						class="rounded-[var(--radius-sm)] px-3.5 py-2 text-[14px] font-medium transition-opacity disabled:opacity-50"
						style="color: var(--text-muted); background: var(--surface-sunk);"
					>
						{savingDraft ? 'Saving…' : 'Save Draft'}
					</button>
				</div>
				<button
					onclick={handleSend}
					disabled={sending || savingDraft || uploadingCount > 0}
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
