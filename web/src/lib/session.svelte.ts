import * as jmap from './jmap';

const STORAGE_KEY = 'litterae-session';

class SessionState {
	token = $state<string | null>(null);
	accountId = $state<string | null>(null);
	address = $state<string | null>(null);

	get isUnlocked() {
		return this.token !== null;
	}
}

// Module-level singleton. Persisted to sessionStorage (survives a
// refresh, cleared when the tab closes) rather than localStorage -- the
// server already expires idle tokens on its own (30 min), so this is
// just avoiding the annoying case, not trying to outlive the tab.
export const session = new SessionState();

if (typeof sessionStorage !== 'undefined') {
	const saved = sessionStorage.getItem(STORAGE_KEY);
	if (saved) {
		try {
			const parsed = JSON.parse(saved);
			session.token = parsed.token ?? null;
			session.accountId = parsed.accountId ?? null;
			session.address = parsed.address ?? null;
		} catch {
			sessionStorage.removeItem(STORAGE_KEY);
		}
	}
}

function persist() {
	if (typeof sessionStorage === 'undefined') return;
	if (session.token) {
		sessionStorage.setItem(
			STORAGE_KEY,
			JSON.stringify({ token: session.token, accountId: session.accountId, address: session.address })
		);
	} else {
		sessionStorage.removeItem(STORAGE_KEY);
	}
}

export async function unlock(localPart: string, domain: string, password: string) {
	const result = await jmap.unlock(localPart, domain, password);
	session.token = result.token;
	session.accountId = result.accountId;
	session.address = `${localPart}@${domain}`;
	persist();
}

export async function lock() {
	if (session.token) {
		await jmap.lock(session.token);
	}
	session.token = null;
	session.accountId = null;
	session.address = null;
	persist();
}

// The backend session can end without the frontend doing anything (idle
// timeout, server restart, an explicit revoke) -- when that happens the
// next JMAP call 401s, and we clear local state immediately rather than
// leaving a stale "unlocked" UI up.
jmap.setUnauthorizedHandler(() => {
	session.token = null;
	session.accountId = null;
	session.address = null;
	persist();
});
