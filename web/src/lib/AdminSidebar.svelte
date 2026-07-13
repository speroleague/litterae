<script lang="ts">
	import { page } from '$app/state';
	import { GlobeIcon, UsersIcon, StackIcon, FileTextIcon } from 'phosphor-svelte';

	let { onNavigate }: { onNavigate?: () => void } = $props();

	const NAV = [
		{ href: '/console/domains', label: 'Domains', icon: GlobeIcon },
		{ href: '/console/accounts', label: 'Accounts', icon: UsersIcon },
		{ href: '/console/queue', label: 'Queue', icon: StackIcon },
		{ href: '/console/logs', label: 'Logs', icon: FileTextIcon }
	];

	const path = $derived(page.url.pathname);
</script>

<nav class="flex flex-col gap-0.5 p-2">
	{#each NAV as item (item.href)}
		{@const Icon = item.icon}
		{@const active = path.startsWith(item.href)}
		<a
			href={item.href}
			onclick={onNavigate}
			class="flex items-center gap-3 rounded-[var(--radius-sm)] px-3 py-2.5 text-[14px] font-medium transition-colors"
			style={active ? 'background: var(--accent); color: white;' : 'color: var(--text-muted);'}
		>
			<Icon size={17} weight={active ? 'fill' : 'regular'} />
			{item.label}
		</a>
	{/each}
</nav>
