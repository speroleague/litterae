<script lang="ts">
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { fade, fly } from 'svelte/transition';
	import { SignOutIcon, ListIcon, XIcon } from 'phosphor-svelte';
	import { adminSession, adminLogout } from '$lib/adminSession.svelte';
	import ThemeToggle from '$lib/ThemeToggle.svelte';
	import AdminSidebar from '$lib/AdminSidebar.svelte';

	let { children } = $props();

	const path = $derived(page.url.pathname);
	const isLoginPage = $derived(path === '/console');
	const isChangePasswordPage = $derived(path === '/console/change-password');

	let drawerOpen = $state(false);

	$effect(() => {
		drawerOpen = false;
		if (!adminSession.isAuthenticated) {
			if (!isLoginPage) goto('/console');
			return;
		}
		if (adminSession.mustChangePassword) {
			if (!isChangePasswordPage) goto('/console/change-password');
			return;
		}
		if (isLoginPage || isChangePasswordPage) {
			goto('/console/domains');
		}
	});

	async function handleLogout() {
		await adminLogout();
		await goto('/console');
	}
</script>

{#if isLoginPage || isChangePasswordPage}
	{@render children()}
{:else if adminSession.isAuthenticated && !adminSession.mustChangePassword}
	<div class="mx-auto flex min-h-screen max-w-5xl">
		<aside class="hidden w-56 shrink-0 sm:block" style="border-right: 1px solid var(--border);">
			<div class="px-4 py-4">
				<h1 class="text-lg font-semibold" style="color: var(--text);">Admin</h1>
				<p class="truncate text-xs" style="color: var(--text-faint);">{adminSession.username}</p>
			</div>
			<AdminSidebar />
		</aside>

		{#if drawerOpen}
			<button
				aria-label="Close menu"
				class="fixed inset-0 z-30 cursor-default sm:hidden"
				style="background: rgba(0,0,0,0.3);"
				onclick={() => (drawerOpen = false)}
				transition:fade={{ duration: 150 }}
			></button>
			<aside
				class="fixed inset-y-0 left-0 z-40 flex w-64 max-w-[80vw] flex-col sm:hidden"
				style="background: var(--surface); border-right: 1px solid var(--border);"
				transition:fly={{ x: -256, duration: 200 }}
			>
				<div class="flex items-center justify-between px-3 py-3" style="border-bottom: 1px solid var(--border);">
					<span class="text-sm font-semibold" style="color: var(--text);">Admin</span>
					<button
						onclick={() => (drawerOpen = false)}
						aria-label="Close menu"
						class="flex h-9 w-9 items-center justify-center rounded-full"
						style="color: var(--text-muted);"
					>
						<XIcon size={18} />
					</button>
				</div>
				<div class="min-h-0 flex-1">
					<AdminSidebar onNavigate={() => (drawerOpen = false)} />
				</div>
			</aside>
		{/if}

		<div class="flex min-w-0 flex-1 flex-col">
			<header
				class="flex items-center justify-between px-4 py-4 sm:px-6"
				style="border-bottom: 1px solid var(--border);"
			>
				<button
					onclick={() => (drawerOpen = !drawerOpen)}
					aria-label="Open menu"
					class="flex h-11 w-11 items-center justify-center rounded-full text-[var(--text-muted)] transition-colors hover:bg-[var(--surface-hover)] sm:hidden"
				>
					<ListIcon size={20} />
				</button>
				<div class="min-w-0 sm:hidden">
					<h1 class="truncate text-lg font-semibold" style="color: var(--text);">Admin</h1>
					<p class="truncate text-xs" style="color: var(--text-faint);">{adminSession.username}</p>
				</div>
				<div class="ml-auto flex shrink-0 items-center">
					<ThemeToggle />
					<button
						onclick={handleLogout}
						aria-label="Log out"
						class="flex h-11 w-11 items-center justify-center rounded-full text-[var(--text-muted)] transition-colors hover:bg-[color-mix(in_oklch,var(--danger)_15%,transparent)] hover:text-[var(--danger)]"
					>
						<SignOutIcon size={20} />
					</button>
				</div>
			</header>

			<main class="flex-1 px-4 py-5 sm:px-6">
				{@render children()}
			</main>
		</div>
	</div>
{/if}
