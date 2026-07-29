import * as admin from './admin';

const STORAGE_KEY = 'litterae-admin-session';

class AdminSessionState {
	token = $state<string | null>(null);
	username = $state<string | null>(null);
	mustChangePassword = $state(false);
	// Set at login when the account has TOTP enabled; cleared once
	// `/admin/mfa/verify` succeeds. While true, every endpoint except
	// verify is server-side FORBIDDEN, mirroring `mustChangePassword`.
	mfaPending = $state(false);
	// Whether the account currently has TOTP configured at all -- distinct
	// from `mfaPending` (a session-scoped gate). Used only to decide what
	// the security page shows; kept in sync at login, confirm, and disable.
	totpEnabled = $state(false);

	get isAuthenticated() {
		return this.token !== null;
	}
}

// Separate from $lib/session.svelte.ts on purpose: admin and mailbox
// credentials are different systems entirely (spec's own "separate admin
// from user" hardening principle), so they get separate session state and
// separate storage keys rather than sharing anything.
export const adminSession = new AdminSessionState();

if (typeof sessionStorage !== 'undefined') {
	const saved = sessionStorage.getItem(STORAGE_KEY);
	if (saved) {
		try {
			const parsed = JSON.parse(saved);
			adminSession.token = parsed.token ?? null;
			adminSession.username = parsed.username ?? null;
			adminSession.mustChangePassword = parsed.mustChangePassword ?? false;
			adminSession.mfaPending = parsed.mfaPending ?? false;
			adminSession.totpEnabled = parsed.totpEnabled ?? false;
		} catch {
			sessionStorage.removeItem(STORAGE_KEY);
		}
	}
}

function persist() {
	if (typeof sessionStorage === 'undefined') return;
	if (adminSession.token) {
		sessionStorage.setItem(
			STORAGE_KEY,
			JSON.stringify({
				token: adminSession.token,
				username: adminSession.username,
				mustChangePassword: adminSession.mustChangePassword,
				mfaPending: adminSession.mfaPending,
				totpEnabled: adminSession.totpEnabled
			})
		);
	} else {
		sessionStorage.removeItem(STORAGE_KEY);
	}
}

export async function adminLogin(username: string, password: string) {
	const result = await admin.login(username, password);
	adminSession.token = result.token;
	adminSession.username = username;
	adminSession.mustChangePassword = result.mustChangePassword;
	adminSession.mfaPending = result.mfaRequired;
	adminSession.totpEnabled = result.mfaRequired;
	persist();
}

export async function adminChangePassword(currentPassword: string, newPassword: string) {
	if (!adminSession.token) return;
	await admin.changePassword(adminSession.token, currentPassword, newPassword);
	adminSession.mustChangePassword = false;
	persist();
}

export async function adminMfaVerify(code: string) {
	if (!adminSession.token) return;
	const result = await admin.mfaVerify(adminSession.token, code);
	adminSession.mfaPending = false;
	adminSession.mustChangePassword = result.mustChangePassword;
	persist();
}

export async function adminMfaEnroll(): Promise<{ secret: string; otpauthUrl: string }> {
	if (!adminSession.token) throw new Error('not logged in');
	return admin.mfaEnroll(adminSession.token);
}

export async function adminMfaConfirm(code: string): Promise<string[]> {
	if (!adminSession.token) throw new Error('not logged in');
	const result = await admin.mfaConfirm(adminSession.token, code);
	adminSession.totpEnabled = true;
	persist();
	return result.recoveryCodes;
}

export async function adminMfaDisable(password: string) {
	if (!adminSession.token) return;
	await admin.mfaDisable(adminSession.token, password);
	adminSession.totpEnabled = false;
	persist();
}

export async function adminLogout() {
	if (adminSession.token) {
		await admin.logout(adminSession.token);
	}
	adminSession.token = null;
	adminSession.username = null;
	adminSession.mustChangePassword = false;
	adminSession.mfaPending = false;
	adminSession.totpEnabled = false;
	persist();
}

// The backend session can end without the frontend doing anything (idle
// timeout, server restart, an explicit revoke) -- when that happens the
// next authenticated request 401s, and we clear local state immediately
// rather than leaving a stale "logged in" UI up.
admin.setUnauthorizedHandler(() => {
	adminSession.token = null;
	adminSession.username = null;
	adminSession.mustChangePassword = false;
	adminSession.mfaPending = false;
	adminSession.totpEnabled = false;
	persist();
});
