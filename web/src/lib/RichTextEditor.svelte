<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { Editor } from '@tiptap/core';
	import StarterKit from '@tiptap/starter-kit';
	import { TextStyle } from '@tiptap/extension-text-style';
	import { Color } from '@tiptap/extension-color';
	import Image from '@tiptap/extension-image';
	import {
		TextBIcon,
		TextItalicIcon,
		TextUnderlineIcon,
		TextHOneIcon,
		TextHTwoIcon,
		TextHThreeIcon,
		ListBulletsIcon,
		ListNumbersIcon,
		QuotesIcon,
		CodeIcon,
		LinkIcon,
		ImageSquareIcon,
		PaletteIcon
	} from 'phosphor-svelte';
	import { session } from '$lib/session.svelte';
	import { uploadAttachment } from '$lib/jmap';
	import Dialog from './Dialog.svelte';

	let { html = $bindable('') }: { html: string } = $props();

	// The same 6 hex values `compose_html::ALLOWED_COLOR_STYLES` allowlists
	// server-side, as `"color: #RRGGBB"` strings -- that's the actual
	// security boundary. This list is only a UX convenience so the picker
	// doesn't offer colors the server would strip; it must be kept in sync
	// by hand, there's no way to share the literal across the wire.
	const COLORS = ['#1a1a1a', '#d92626', '#d97706', '#16a34a', '#2563eb', '#7c3aed'];

	let editorEl: HTMLDivElement | undefined = $state();
	// `$state.raw`, not `$state` -- an `Editor` is a complex class
	// instance with lots of internal mutable state that TipTap manages
	// itself. Deep-proxying it (what plain `$state()` does for objects)
	// would make every read of `editor.getHTML()`/`.isActive()` anywhere
	// track that internal state as a reactive dependency, which given
	// how constantly it mutates during typing caused a genuine infinite
	// effect loop (`effect_update_depth_exceeded`) during testing.
	// `$state.raw` only tracks reassignment of `editor` itself.
	let editor: Editor | undefined = $state.raw();
	let version = $state(0);
	// The last html value editor and the bindable `html` prop are known
	// to agree on -- see the sync effect below for why.
	let lastSyncedHtml = $state('');
	let colorPickerOpen = $state(false);
	let linkDialogOpen = $state(false);
	let linkUrl = $state('');
	let uploadingImage = $state(false);
	let error = $state<string | null>(null);
	let fileInput: HTMLInputElement | undefined = $state();

	function active(name: string, attrs?: Record<string, unknown>): boolean {
		void version;
		return editor?.isActive(name, attrs) ?? false;
	}

	// The CSP's `img-src` has no `cid:` scheme (rightly -- no browser can
	// ever resolve one), so a freshly-inserted image can't use
	// `cid:u{id}` as its live `src` while composing. Instead it gets a
	// local `blob:` URL (from the same File just uploaded) for the
	// editor's own preview, tracked here so `onUpdate` can rewrite it
	// back to `cid:u{id}` in the HTML that actually leaves this
	// component -- the server only ever sees the cid form. A *resumed*
	// draft's `bodyHtml` never hits this path: its images already come
	// back as resolved `data:` URIs from the server (see
	// `html_sanitize.rs`), which the browser renders natively.
	const blobUrlToUploadId = new Map<string, string>();

	async function handleImageFile(file: File) {
		const token = session.token;
		if (!token || !editor) return;
		uploadingImage = true;
		error = null;
		try {
			const uploaded = await uploadAttachment(token, file);
			const previewUrl = URL.createObjectURL(file);
			blobUrlToUploadId.set(previewUrl, uploaded.blobId);
			editor.chain().focus().setImage({ src: previewUrl }).run();
		} catch {
			error = 'Could not insert this image (rejected or too large).';
		} finally {
			uploadingImage = false;
		}
	}

	function onFilePicked(e: Event) {
		const picked = (e.target as HTMLInputElement).files?.[0];
		if (picked) void handleImageFile(picked);
		if (fileInput) fileInput.value = '';
	}

	function isSafeLinkUrl(url: string): boolean {
		try {
			return ['http:', 'https:', 'mailto:'].includes(new URL(url).protocol);
		} catch {
			return false;
		}
	}

	function openLinkDialog() {
		linkUrl = editor?.getAttributes('link').href ?? '';
		linkDialogOpen = true;
	}

	function applyLink() {
		const url = linkUrl.trim();
		if (!editor) return;
		if (!url) {
			editor.chain().focus().extendMarkRange('link').unsetLink().run();
		} else if (isSafeLinkUrl(url)) {
			editor.chain().focus().extendMarkRange('link').setLink({ href: url }).run();
		}
		linkDialogOpen = false;
	}

	onMount(() => {
		editor = new Editor({
			element: editorEl,
			extensions: [
				StarterKit.configure({
					strike: false,
					horizontalRule: false,
					heading: { levels: [1, 2, 3] },
					link: { openOnClick: false, autolink: false }
				}),
				TextStyle,
				Color,
				Image.configure({ inline: true, allowBase64: false })
			],
			content: html || '',
			onUpdate: ({ editor }) => {
				let out = editor.getHTML();
				for (const [blobUrl, uploadId] of blobUrlToUploadId) {
					out = out.split(blobUrl).join(`cid:${uploadId}`);
				}
				lastSyncedHtml = out;
				html = out;
			},
			onTransaction: () => {
				version++;
			},
			editorProps: {
				handlePaste: (_view, event) => {
					const files = Array.from(event.clipboardData?.files ?? []).filter((f) =>
						f.type.startsWith('image/')
					);
					if (files.length === 0) return false;
					files.forEach((f) => void handleImageFile(f));
					return true;
				},
				handleDrop: (_view, event) => {
					const files = Array.from(event.dataTransfer?.files ?? []).filter((f) =>
						f.type.startsWith('image/')
					);
					if (files.length === 0) return false;
					files.forEach((f) => void handleImageFile(f));
					return true;
				}
			}
		});
	});

	onDestroy(() => {
		editor?.destroy();
	});

	// Only push external `html` into the editor when it didn't just come
	// from the editor's own `onUpdate` -- otherwise every keystroke would
	// round-trip through this effect and reset the cursor. Compared
	// against `lastSyncedHtml` (the last value editor and `html` are
	// known to agree on), not a fresh `editor.getHTML()` call -- TipTap's
	// serialization isn't guaranteed byte-identical across calls in every
	// edge case, and diffing against a live call from inside this effect
	// while also driving a mutation through `setContent` (which itself
	// fires `onUpdate`) produced a genuine infinite effect loop during
	// testing.
	$effect(() => {
		const incoming = html;
		if (editor && incoming !== lastSyncedHtml) {
			lastSyncedHtml = incoming;
			editor.commands.setContent(incoming);
		}
	});
</script>

<div class="flex flex-1 flex-col">
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<div
		class="flex flex-wrap items-center gap-0.5 px-3 py-1.5"
		style="border-bottom: 1px solid var(--border);"
		onmousedown={(e) => {
			// Default `mousedown` behavior moves focus to the clicked
			// button, which blurs the editor and collapses whatever
			// selection a toolbar command (bold/heading/link/...) was
			// about to act on -- delegated here once for every button in
			// the toolbar rather than repeated on each one.
			if ((e.target as HTMLElement).closest('button')) e.preventDefault();
		}}
	>
		<button
			type="button"
			onclick={() => editor?.chain().focus().toggleBold().run()}
			aria-label="Bold"
			aria-pressed={active('bold')}
			class="flex h-7 w-7 items-center justify-center rounded-[var(--radius-sm)]"
			style="color: {active('bold') ? 'var(--accent)' : 'var(--text-muted)'}; background: {active('bold')
				? 'var(--accent-weak)'
				: 'transparent'};"
		>
			<TextBIcon size={15} />
		</button>
		<button
			type="button"
			onclick={() => editor?.chain().focus().toggleItalic().run()}
			aria-label="Italic"
			aria-pressed={active('italic')}
			class="flex h-7 w-7 items-center justify-center rounded-[var(--radius-sm)]"
			style="color: {active('italic') ? 'var(--accent)' : 'var(--text-muted)'}; background: {active('italic')
				? 'var(--accent-weak)'
				: 'transparent'};"
		>
			<TextItalicIcon size={15} />
		</button>
		<button
			type="button"
			onclick={() => editor?.chain().focus().toggleUnderline().run()}
			aria-label="Underline"
			aria-pressed={active('underline')}
			class="flex h-7 w-7 items-center justify-center rounded-[var(--radius-sm)]"
			style="color: {active('underline') ? 'var(--accent)' : 'var(--text-muted)'}; background: {active(
				'underline'
			)
				? 'var(--accent-weak)'
				: 'transparent'};"
		>
			<TextUnderlineIcon size={15} />
		</button>

		<span class="mx-1 h-4 w-px" style="background: var(--border);"></span>

		<button
			type="button"
			onclick={() => editor?.chain().focus().toggleHeading({ level: 1 }).run()}
			aria-label="Heading 1"
			aria-pressed={active('heading', { level: 1 })}
			class="flex h-7 w-7 items-center justify-center rounded-[var(--radius-sm)]"
			style="color: {active('heading', { level: 1 }) ? 'var(--accent)' : 'var(--text-muted)'}; background: {active(
				'heading',
				{ level: 1 }
			)
				? 'var(--accent-weak)'
				: 'transparent'};"
		>
			<TextHOneIcon size={15} />
		</button>
		<button
			type="button"
			onclick={() => editor?.chain().focus().toggleHeading({ level: 2 }).run()}
			aria-label="Heading 2"
			aria-pressed={active('heading', { level: 2 })}
			class="flex h-7 w-7 items-center justify-center rounded-[var(--radius-sm)]"
			style="color: {active('heading', { level: 2 }) ? 'var(--accent)' : 'var(--text-muted)'}; background: {active(
				'heading',
				{ level: 2 }
			)
				? 'var(--accent-weak)'
				: 'transparent'};"
		>
			<TextHTwoIcon size={15} />
		</button>
		<button
			type="button"
			onclick={() => editor?.chain().focus().toggleHeading({ level: 3 }).run()}
			aria-label="Heading 3"
			aria-pressed={active('heading', { level: 3 })}
			class="flex h-7 w-7 items-center justify-center rounded-[var(--radius-sm)]"
			style="color: {active('heading', { level: 3 }) ? 'var(--accent)' : 'var(--text-muted)'}; background: {active(
				'heading',
				{ level: 3 }
			)
				? 'var(--accent-weak)'
				: 'transparent'};"
		>
			<TextHThreeIcon size={15} />
		</button>

		<span class="mx-1 h-4 w-px" style="background: var(--border);"></span>

		<div class="relative">
			<button
				type="button"
				onclick={() => (colorPickerOpen = !colorPickerOpen)}
				aria-label="Text color"
				class="flex h-7 w-7 items-center justify-center rounded-[var(--radius-sm)]"
				style="color: var(--text-muted);"
			>
				<PaletteIcon size={15} />
			</button>
			{#if colorPickerOpen}
				<div
					class="absolute top-full left-0 z-10 mt-1 flex gap-1 rounded-[var(--radius-sm)] p-1.5"
					style="background: var(--surface); border: 1px solid var(--border); box-shadow: 0 4px 12px rgba(0,0,0,0.15);"
				>
					{#each COLORS as color (color)}
						<button
							type="button"
							aria-label={`Color ${color}`}
							onclick={() => {
								editor?.chain().focus().setColor(color).run();
								colorPickerOpen = false;
							}}
							class="h-5 w-5 rounded-full"
							style="background: {color}; border: 1px solid var(--border);"
						></button>
					{/each}
					<button
						type="button"
						aria-label="Clear color"
						onclick={() => {
							editor?.chain().focus().unsetColor().run();
							colorPickerOpen = false;
						}}
						class="flex h-5 w-5 items-center justify-center rounded-full text-[10px]"
						style="border: 1px solid var(--border); color: var(--text-faint);"
					>
						×
					</button>
				</div>
			{/if}
		</div>

		<span class="mx-1 h-4 w-px" style="background: var(--border);"></span>

		<button
			type="button"
			onclick={() => editor?.chain().focus().toggleBulletList().run()}
			aria-label="Bulleted list"
			aria-pressed={active('bulletList')}
			class="flex h-7 w-7 items-center justify-center rounded-[var(--radius-sm)]"
			style="color: {active('bulletList') ? 'var(--accent)' : 'var(--text-muted)'}; background: {active(
				'bulletList'
			)
				? 'var(--accent-weak)'
				: 'transparent'};"
		>
			<ListBulletsIcon size={15} />
		</button>
		<button
			type="button"
			onclick={() => editor?.chain().focus().toggleOrderedList().run()}
			aria-label="Numbered list"
			aria-pressed={active('orderedList')}
			class="flex h-7 w-7 items-center justify-center rounded-[var(--radius-sm)]"
			style="color: {active('orderedList') ? 'var(--accent)' : 'var(--text-muted)'}; background: {active(
				'orderedList'
			)
				? 'var(--accent-weak)'
				: 'transparent'};"
		>
			<ListNumbersIcon size={15} />
		</button>

		<span class="mx-1 h-4 w-px" style="background: var(--border);"></span>

		<button
			type="button"
			onclick={() => editor?.chain().focus().toggleBlockquote().run()}
			aria-label="Blockquote"
			aria-pressed={active('blockquote')}
			class="flex h-7 w-7 items-center justify-center rounded-[var(--radius-sm)]"
			style="color: {active('blockquote') ? 'var(--accent)' : 'var(--text-muted)'}; background: {active(
				'blockquote'
			)
				? 'var(--accent-weak)'
				: 'transparent'};"
		>
			<QuotesIcon size={15} />
		</button>
		<button
			type="button"
			onclick={() => editor?.chain().focus().toggleCodeBlock().run()}
			aria-label="Code block"
			aria-pressed={active('codeBlock')}
			class="flex h-7 w-7 items-center justify-center rounded-[var(--radius-sm)]"
			style="color: {active('codeBlock') ? 'var(--accent)' : 'var(--text-muted)'}; background: {active(
				'codeBlock'
			)
				? 'var(--accent-weak)'
				: 'transparent'};"
		>
			<CodeIcon size={15} />
		</button>

		<span class="mx-1 h-4 w-px" style="background: var(--border);"></span>

		<button
			type="button"
			onclick={openLinkDialog}
			aria-label="Link"
			aria-pressed={active('link')}
			class="flex h-7 w-7 items-center justify-center rounded-[var(--radius-sm)]"
			style="color: {active('link') ? 'var(--accent)' : 'var(--text-muted)'}; background: {active('link')
				? 'var(--accent-weak)'
				: 'transparent'};"
		>
			<LinkIcon size={15} />
		</button>
		<input
			bind:this={fileInput}
			type="file"
			accept="image/*"
			class="hidden"
			onchange={onFilePicked}
		/>
		<button
			type="button"
			onclick={() => fileInput?.click()}
			disabled={uploadingImage}
			aria-label="Insert image"
			class="flex h-7 w-7 items-center justify-center rounded-[var(--radius-sm)] disabled:opacity-50"
			style="color: var(--text-muted);"
		>
			<ImageSquareIcon size={15} />
		</button>
		{#if uploadingImage}
			<span class="text-xs" style="color: var(--text-faint);">Uploading…</span>
		{/if}
	</div>

	{#if error}
		<p class="px-3 pt-1.5 text-xs" style="color: var(--danger);">{error}</p>
	{/if}

	<!-- svelte-ignore a11y_no_static_element_interactions, a11y_click_events_have_key_events -->
	<div
		bind:this={editorEl}
		class="tiptap-body min-h-[280px] flex-1 overflow-y-auto px-4 py-3 text-[15px] leading-relaxed outline-none"
		style="color: var(--text);"
		onclick={(e) => {
			// TipTap's contenteditable only occupies its own content
			// height, not this wrapper's `min-h`, so clicking the empty
			// padded area below a short document (the common case: a
			// blank compose box) would otherwise do nothing. Only
			// re-focus when the click actually lands on this wrapper
			// itself, not on the editable content (which already handles
			// its own focus/cursor placement).
			if (e.target === editorEl) editor?.commands.focus('end');
		}}
	></div>
</div>

<Dialog bind:open={linkDialogOpen}>
	<h2 class="mb-2 text-[15px] font-semibold" style="color: var(--text);">Link</h2>
	<input
		type="text"
		placeholder="https://example.com"
		bind:value={linkUrl}
		class="w-full rounded-[var(--radius-sm)] px-2.5 py-2 text-sm outline-none"
		style="background: var(--surface-sunk); color: var(--text); border: 1px solid var(--border);"
	/>
	<div class="mt-3 flex justify-end gap-2">
		<button
			onclick={() => (linkDialogOpen = false)}
			class="rounded-[var(--radius-sm)] px-3.5 py-2 text-[14px] font-medium"
			style="color: var(--text-muted); background: var(--surface-sunk);"
		>
			Cancel
		</button>
		<button
			onclick={applyLink}
			class="rounded-[var(--radius-sm)] px-3.5 py-2 text-[14px] font-medium text-white"
			style="background: var(--accent);"
		>
			Apply
		</button>
	</div>
</Dialog>

<style>
	:global(.tiptap-body p) {
		margin: 0 0 0.6em 0;
	}
	:global(.tiptap-body h1),
	:global(.tiptap-body h2),
	:global(.tiptap-body h3) {
		margin: 0.6em 0 0.3em 0;
		font-weight: 600;
		line-height: 1.3;
	}
	:global(.tiptap-body h1) {
		font-size: 1.4em;
	}
	:global(.tiptap-body h2) {
		font-size: 1.2em;
	}
	:global(.tiptap-body h3) {
		font-size: 1.05em;
	}
	:global(.tiptap-body ul),
	:global(.tiptap-body ol) {
		margin: 0 0 0.6em 0;
		padding-left: 1.4em;
	}
	:global(.tiptap-body blockquote) {
		margin: 0 0 0.6em 0;
		padding-left: 0.8em;
		border-left: 3px solid var(--border);
		color: var(--text-muted);
	}
	:global(.tiptap-body pre) {
		margin: 0 0 0.6em 0;
		padding: 0.6em 0.8em;
		border-radius: var(--radius-sm);
		background: var(--surface-sunk);
		overflow-x: auto;
	}
	:global(.tiptap-body code) {
		font-family: ui-monospace, monospace;
		font-size: 0.9em;
	}
	:global(.tiptap-body img) {
		max-width: 100%;
		border-radius: var(--radius-sm);
	}
	:global(.tiptap-body a) {
		color: var(--accent);
		text-decoration: underline;
	}
</style>
