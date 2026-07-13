// Relative paths: this app is served from the same Caddy origin that
// reverse-proxies /admin/* to the litterae admin API (see ../../Caddyfile
// -- same same-origin reasoning as $lib/jmap.ts).

export class AdminError extends Error {
	status: number;
	constructor(message: string, status: number) {
		super(message);
		this.status = status;
	}
}

// Set by $lib/adminSession.svelte.ts so a 401 on any *authenticated*
// request (one sent with a bearer token) clears the session immediately,
// rather than leaving stale UI up until the user notices something's
// broken. Login itself can 401 on bad credentials without tripping this
// -- see the `authenticated` flag below.
let onUnauthorized: (() => void) | null = null;
export function setUnauthorizedHandler(handler: () => void) {
	onUnauthorized = handler;
}

async function request<T>(path: string, init: RequestInit = {}, authenticated = false): Promise<T> {
	const res = await fetch(path, init);
	if (res.status === 401 && authenticated) {
		onUnauthorized?.();
	}
	if (!res.ok) {
		throw new AdminError(`${path} failed: ${res.status}`, res.status);
	}
	if (res.status === 204) return undefined as T;
	return res.json() as Promise<T>;
}

function authHeaders(token: string): HeadersInit {
	return { authorization: `Bearer ${token}` };
}

export interface StatusResponse {
	hasAdmin: boolean;
	domainCount: number;
	accountCount: number;
}

export async function getStatus(): Promise<StatusResponse> {
	return request('/admin/status');
}

export async function login(username: string, password: string): Promise<{ token: string; mustChangePassword: boolean }> {
	return request('/admin/login', {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ username, password })
	});
}

export async function logout(token: string): Promise<void> {
	await fetch('/admin/logout', { method: 'POST', headers: authHeaders(token) });
}

export async function changePassword(
	token: string,
	currentPassword: string,
	newPassword: string
): Promise<void> {
	await request(
		'/admin/change-password',
		{
			method: 'POST',
			headers: { 'content-type': 'application/json', ...authHeaders(token) },
			body: JSON.stringify({ currentPassword, newPassword })
		},
		true
	);
}

export interface DomainObject {
	id: number;
	name: string;
	catchAllLocalPart: string | null;
	verificationToken: string;
	verified: boolean;
}

export async function listDomains(token: string): Promise<DomainObject[]> {
	return request('/admin/domains', { headers: authHeaders(token) }, true);
}

export async function createDomain(
	token: string,
	name: string,
	catchAllLocalPart: string | null
): Promise<DomainObject> {
	return request(
		'/admin/domains',
		{
			method: 'POST',
			headers: { 'content-type': 'application/json', ...authHeaders(token) },
			body: JSON.stringify({ name, catchAllLocalPart })
		},
		true
	);
}

export async function setCatchAll(token: string, id: number, catchAllLocalPart: string | null): Promise<void> {
	await request(
		`/admin/domains/${id}`,
		{
			method: 'PATCH',
			headers: { 'content-type': 'application/json', ...authHeaders(token) },
			body: JSON.stringify({ catchAllLocalPart })
		},
		true
	);
}

export async function deleteDomain(token: string, id: number): Promise<void> {
	await request(`/admin/domains/${id}`, { method: 'DELETE', headers: authHeaders(token) }, true);
}

export interface DkimRecord {
	domain: string;
	selector: string;
	recordName: string;
	recordValue: string;
}

export async function getDomainDkim(token: string, id: number): Promise<DkimRecord> {
	return request(`/admin/domains/${id}/dkim`, { headers: authHeaders(token) }, true);
}

export interface VerifyDomainResult {
	verified: boolean;
	recordName: string;
	recordValue: string;
}

export async function verifyDomain(token: string, id: number): Promise<VerifyDomainResult> {
	return request(`/admin/domains/${id}/verify`, { method: 'POST', headers: authHeaders(token) }, true);
}

export interface AccountObject {
	id: number;
	address: string;
	createdAt: number;
}

export async function listAccounts(token: string): Promise<AccountObject[]> {
	return request('/admin/accounts', { headers: authHeaders(token) }, true);
}

export async function createAccount(
	token: string,
	localPart: string,
	domain: string,
	password: string
): Promise<AccountObject> {
	return request(
		'/admin/accounts',
		{
			method: 'POST',
			headers: { 'content-type': 'application/json', ...authHeaders(token) },
			body: JSON.stringify({ localPart, domain, password })
		},
		true
	);
}

export async function deleteAccount(token: string, id: number): Promise<void> {
	await request(`/admin/accounts/${id}`, { method: 'DELETE', headers: authHeaders(token) }, true);
}

export interface QueueMetrics {
	ready: number;
	claimed: number;
	deferred: number;
	delivered: number;
	failed: number;
	expired: number;
}

export interface RecentFailure {
	id: number;
	rcptTo: string;
	domain: string;
	attempts: number;
	lastCode: number | null;
	lastStatus: string | null;
	lastDetail: string | null;
}

export interface QueueStatusResponse {
	metrics: QueueMetrics;
	recentFailures: RecentFailure[];
}

export async function getQueueStatus(token: string): Promise<QueueStatusResponse> {
	return request('/admin/queue', { headers: authHeaders(token) }, true);
}

export interface LogEntry {
	timestamp: string;
	level: string;
	target: string;
	fields: Record<string, unknown> & { message: string };
}

export interface LogQuery {
	since?: number;
	until?: number;
	level?: string;
}

export async function getLogs(token: string, query: LogQuery = {}): Promise<LogEntry[]> {
	const params = new URLSearchParams();
	if (query.since !== undefined) params.set('since', String(query.since));
	if (query.until !== undefined) params.set('until', String(query.until));
	if (query.level) params.set('level', query.level);
	const qs = params.toString();
	return request(`/admin/logs${qs ? `?${qs}` : ''}`, { headers: authHeaders(token) }, true);
}
