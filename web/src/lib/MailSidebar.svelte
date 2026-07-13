<script lang="ts">
	import {
		TrayIcon,
		ArchiveIcon,
		TrashIcon,
		PaperPlaneTiltIcon,
		NotePencilIcon,
		ShieldWarningIcon,
		FileTextIcon,
		StarIcon
	} from 'phosphor-svelte';
	import { mailNav, selectView, FLAGGED_VIEW } from '$lib/mailNav.svelte';
	import { openNewMessage } from '$lib/composeState.svelte';

	const ROLE_ICONS: Record<string, typeof TrayIcon> = {
		inbox: TrayIcon,
		archive: ArchiveIcon,
		trash: TrashIcon,
		sent: PaperPlaneTiltIcon,
		drafts: NotePencilIcon,
		junk: ShieldWarningIcon
	};
</script>

<div class="flex h-full flex-col">
	<div class="p-3">
		<button
			onclick={openNewMessage}
			class="flex w-full items-center justify-center gap-2 rounded-[var(--radius-sm)] py-2.5 text-[14px] font-medium text-white transition-opacity hover:opacity-90"
			style="background: var(--accent);"
		>
			<NotePencilIcon size={17} weight="bold" />
			New Message
		</button>
	</div>

	<nav class="flex flex-1 flex-col gap-0.5 overflow-y-auto px-2 pb-3">
		{#each mailNav.mailboxes as mailbox (mailbox.id)}
			{@const Icon = ROLE_ICONS[mailbox.role ?? ''] ?? FileTextIcon}
			{@const active = mailNav.activeViewId === mailbox.id}
			<button
				onclick={() => selectView(mailbox.id)}
				class="flex items-center gap-3 rounded-[var(--radius-sm)] px-3 py-2.5 text-left text-[14px] font-medium transition-colors hover:bg-[var(--surface-hover)]"
				style={active ? 'background: var(--accent); color: white;' : 'color: var(--text-muted);'}
			>
				<Icon size={17} weight={active ? 'fill' : 'regular'} />
				<span class="min-w-0 flex-1 truncate">{mailbox.name}</span>
				{#if mailbox.totalEmails > 0}
					<span class="text-xs" style={active ? 'opacity: 0.85;' : 'color: var(--text-faint);'}>
						{mailbox.totalEmails}
					</span>
				{/if}
			</button>
		{/each}
		<button
			onclick={() => selectView(FLAGGED_VIEW)}
			class="flex items-center gap-3 rounded-[var(--radius-sm)] px-3 py-2.5 text-left text-[14px] font-medium transition-colors hover:bg-[var(--surface-hover)]"
			style={mailNav.activeViewId === FLAGGED_VIEW
				? 'background: var(--accent); color: white;'
				: 'color: var(--text-muted);'}
		>
			<StarIcon size={17} weight={mailNav.activeViewId === FLAGGED_VIEW ? 'fill' : 'regular'} />
			<span class="flex-1 truncate text-left">Flagged</span>
		</button>
	</nav>
</div>
