// Empty string = same origin as the page itself. The default deployment
// (docker-compose.yml) serves this app and reverse-proxies /auth/* and
// /jmap/* to the JMAP API from the same Caddy origin, so no cross-origin
// URL is needed. Set VITE_JMAP_URL only if JMAP is genuinely hosted
// elsewhere.
const JMAP_URL = import.meta.env.VITE_JMAP_URL ?? '';

export class JmapError extends Error {}

// Set by $lib/session.svelte.ts so a 401 on an authenticated JMAP call
// clears the session immediately instead of leaving stale UI up.
let onUnauthorized: (() => void) | null = null;
export function setUnauthorizedHandler(handler: () => void) {
	onUnauthorized = handler;
}

export interface EmailAddress {
	name: string | null;
	email: string;
}

export interface EmailObject {
	id: string;
	threadId: string;
	mailboxIds: Record<string, boolean>;
	keywords: Record<string, boolean>;
	from: EmailAddress[];
	to: EmailAddress[];
	subject: string | null;
	receivedAt: string;
	preview: string;
	bodyText: string | null;
	size: number;
	/** This message's own `Message-ID` header. */
	messageId: string | null;
	/** The `Message-ID` of the message this one replied to, if any --
	 * match against a thread sibling's own `messageId` to find it. */
	inReplyToMessageId: string | null;
	/** rspamd's raw score, null if antispam scanning wasn't
	 * configured/reachable for this message. */
	spamScore: number | null;
	/** true = clamd scanned and found nothing, false = clamd found
	 * something, null = not scanned. */
	avClean: boolean | null;
	/** Sanitized HTML body, null if this message has no HTML part. */
	bodyHtml: string | null;
	/** Remote images stripped pending explicit reveal; null iff bodyHtml is null. */
	blockedImageCount: number | null;
	attachments: EmailAttachment[];
}

export interface EmailAttachment {
	blobId: string;
	name: string;
	type: string;
	size: number;
}

export function formatFileSize(bytes: number): string {
	if (bytes < 1024) return `${bytes} B`;
	if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
	return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export interface MailboxObject {
	id: string;
	name: string;
	role: string | null;
	totalEmails: number;
}

export const KEYWORD_FLAGGED = '$flagged';
export const KEYWORD_SEEN = '$seen';
export const KEYWORD_DRAFT = '$draft';

export interface EmailFilter {
	inMailbox?: string;
	hasKeyword?: string;
	notHasKeyword?: string;
	text?: string;
}

export const DEFAULT_PAGE_SIZE = 50;

async function request<T>(path: string, init: RequestInit, authenticated = false): Promise<T> {
	const res = await fetch(`${JMAP_URL}${path}`, init);
	if (res.status === 401 && authenticated) {
		onUnauthorized?.();
	}
	if (!res.ok) {
		throw new JmapError(`${path} failed: ${res.status}`);
	}
	return res.json() as Promise<T>;
}

export async function unlock(
	localPart: string,
	domain: string,
	password: string
): Promise<{ token: string; accountId: string }> {
	return request('/auth/unlock', {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ local_part: localPart, domain, password })
	});
}

export async function lock(token: string): Promise<void> {
	await fetch(`${JMAP_URL}/auth/lock`, {
		method: 'POST',
		headers: { authorization: `Bearer ${token}` }
	});
}

type MethodResponse = [string, Record<string, unknown>, string];

async function callApi(token: string, methodCalls: [string, unknown, string][]): Promise<MethodResponse[]> {
	const body = {
		using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
		methodCalls
	};
	const result = await request<{ methodResponses: MethodResponse[] }>(
		'/jmap/api',
		{
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				authorization: `Bearer ${token}`
			},
			body: JSON.stringify(body)
		},
		true
	);
	return result.methodResponses;
}

export async function getMailboxes(token: string, accountId: string): Promise<MailboxObject[]> {
	const [[, result]] = await callApi(token, [['Mailbox/get', { accountId }, 'c1']]);
	return result.list as MailboxObject[];
}

export interface EmailQueryPage {
	ids: string[];
	total: number;
}

export async function queryEmails(
	token: string,
	accountId: string,
	filter?: EmailFilter,
	position = 0,
	limit: number = DEFAULT_PAGE_SIZE
): Promise<EmailQueryPage> {
	const args: Record<string, unknown> = { accountId, position, limit };
	if (filter && (filter.inMailbox || filter.hasKeyword || filter.notHasKeyword || filter.text)) {
		args.filter = filter;
	}
	const [[, result]] = await callApi(token, [['Email/query', args, 'c1']]);
	return { ids: result.ids as string[], total: result.total as number };
}

export async function getEmails(
	token: string,
	accountId: string,
	ids: string[]
): Promise<EmailObject[]> {
	if (ids.length === 0) return [];
	const [[, result]] = await callApi(token, [['Email/get', { accountId, ids }, 'c1']]);
	return result.list as EmailObject[];
}

export interface MailboxPage {
	emails: EmailObject[];
	total: number;
}

/**
 * List+get for the mail list screen. JMAP allows chaining these in one
 * request via result references; the server doesn't resolve those yet, so
 * this is two round trips for now. `total` is the full match count, not
 * just `emails.length` -- the caller needs it to know whether there's more
 * to page in (a mailbox can easily have more messages than one page).
 */
export async function loadMailbox(
	token: string,
	accountId: string,
	filter?: EmailFilter,
	position = 0,
	limit: number = DEFAULT_PAGE_SIZE
): Promise<MailboxPage> {
	const page = await queryEmails(token, accountId, filter, position, limit);
	const emails = await getEmails(token, accountId, page.ids);
	return { emails, total: page.total };
}

export async function setKeyword(
	token: string,
	accountId: string,
	emailId: string,
	keyword: string,
	value: boolean
): Promise<void> {
	await callApi(token, [
		[
			'Email/set',
			{ accountId, update: { [emailId]: { [`keywords/${keyword}`]: value } } },
			'c1'
		]
	]);
}

export async function moveToMailbox(
	token: string,
	accountId: string,
	emailId: string,
	mailboxId: string
): Promise<void> {
	await callApi(token, [
		[
			'Email/set',
			{ accountId, update: { [emailId]: { [`mailboxIds/${mailboxId}`]: true } } },
			'c1'
		]
	]);
}

/**
 * Matches the server's destroy semantics (spec §4 JMAP object model): the
 * first destroy moves a message to Trash, destroying an already-trashed
 * message deletes it permanently. Same call either way -- the server
 * decides which based on the message's current mailbox.
 */
export async function destroyEmail(token: string, accountId: string, emailId: string): Promise<void> {
	await callApi(token, [['Email/set', { accountId, destroy: [emailId] }, 'c1']]);
}

export interface ComposeAddress {
	name?: string;
	email: string;
}

export interface ComposeInput {
	to: ComposeAddress[];
	cc?: ComposeAddress[];
	bcc?: ComposeAddress[];
	subject?: string;
	bodyText?: string;
	/** JMAP id ("m123") of the message being replied to, if any. */
	inReplyTo?: string;
	/** `blobId`s from prior `uploadAttachment` calls. */
	attachmentBlobIds?: string[];
}

export class JmapSetError extends JmapError {
	constructor(reason: unknown) {
		super(typeof reason === 'object' && reason && 'description' in reason ? String((reason as { description: unknown }).description) : 'Email/set failed');
	}
}

/** Creates a message in Drafts. Used both for "save as draft" and as the
 * first step of "send" (send = save draft, then EmailSubmission/set it). */
export async function saveDraft(
	token: string,
	accountId: string,
	input: ComposeInput
): Promise<{ id: string; threadId: string }> {
	const [[, result]] = await callApi(token, [
		['Email/set', { accountId, create: { draft: input } }, 'c1']
	]);
	const created = (result.created as Record<string, { id: string; threadId: string }> | undefined)?.draft;
	if (!created) {
		throw new JmapSetError((result.notCreated as Record<string, unknown> | undefined)?.draft);
	}
	return created;
}

/** Replaces the body of an existing draft: destroys the old row and
 * creates a fresh one. Simpler and just as correct as an in-place patch,
 * since a draft has no other client state pointing at its message id
 * between saves. */
export async function updateDraft(
	token: string,
	accountId: string,
	emailId: string,
	input: ComposeInput
): Promise<{ id: string; threadId: string }> {
	await destroyEmail(token, accountId, emailId);
	return saveDraft(token, accountId, input);
}

/** Sends an already-created (Drafts) message: DKIM-signs and queues it for
 * delivery, then moves it into Sent with `$draft` cleared. */
export async function submitEmail(
	token: string,
	accountId: string,
	emailId: string,
	rcptTo: string[]
): Promise<void> {
	const [[, result]] = await callApi(token, [
		[
			'EmailSubmission/set',
			{ accountId, create: { sub: { emailId, envelope: { rcptTo: rcptTo.map((email) => ({ email })) } } } },
			'c1'
		]
	]);
	const created = (result.created as Record<string, unknown> | undefined)?.sub;
	if (!created) {
		throw new JmapSetError((result.notCreated as Record<string, unknown> | undefined)?.sub);
	}
}

/** Composes and immediately sends: save as a draft, then submit it. */
export async function sendNewEmail(token: string, accountId: string, input: ComposeInput): Promise<void> {
	const draft = await saveDraft(token, accountId, input);
	const rcptTo = [...input.to, ...(input.cc ?? []), ...(input.bcc ?? [])].map((a) => a.email);
	await submitEmail(token, accountId, draft.id, rcptTo);
}

export async function getThreadEmailIds(token: string, accountId: string, threadId: string): Promise<string[]> {
	const [[, result]] = await callApi(token, [['Thread/get', { accountId, ids: [threadId] }, 'c1']]);
	const list = result.list as { id: string; emailIds: string[] }[] | undefined;
	return list?.[0]?.emailIds ?? [];
}

export interface IdentityObject {
	id: string;
	name: string;
	email: string;
	textSignature: string;
	mayDelete: boolean;
}

/** Litterae has exactly one identity per account (RFC 8621 §6, our own
 * address) -- this always returns it or null if the account is somehow
 * missing one. */
export async function getIdentity(token: string, accountId: string): Promise<IdentityObject | null> {
	const [[, result]] = await callApi(token, [['Identity/get', { accountId }, 'c1']]);
	const list = result.list as IdentityObject[];
	return list[0] ?? null;
}

export async function setIdentitySignature(
	token: string,
	accountId: string,
	identityId: string,
	textSignature: string
): Promise<void> {
	await callApi(token, [
		['Identity/set', { accountId, update: { [identityId]: { textSignature } } }, 'c1']
	]);
}

export interface UploadedBlob {
	accountId: string;
	blobId: string;
	type: string;
	size: number;
}

/** Uploads a file for a not-yet-sent draft attachment. Raw body (the
 * file's own bytes, `Content-Type` set to its own MIME type) rather than
 * `multipart/form-data`, matching JMAP's binary upload semantics. The
 * returned `blobId` (a `u{id}` reference) is passed to `saveDraft`/
 * `updateDraft` via `ComposeInput.attachmentBlobIds` -- uploading alone
 * doesn't attach it to anything yet. */
export async function uploadAttachment(token: string, file: File): Promise<UploadedBlob> {
	return request(
		`/jmap/upload?filename=${encodeURIComponent(file.name)}`,
		{
			method: 'POST',
			headers: {
				authorization: `Bearer ${token}`,
				'content-type': file.type || 'application/octet-stream'
			},
			body: file
		},
		true
	);
}

/** Downloads an attachment (`m{id}.{index}` from a received message, or
 * `u{id}` from a pending upload) and saves it via a throwaway object URL.
 * Deliberately never a bare `<a href>` straight at the JMAP endpoint --
 * that would need the bearer token to ride along in the URL, which
 * `fetch()` avoids by setting it as a header instead. */
export async function downloadAttachment(token: string, blobId: string, filename: string): Promise<void> {
	const res = await fetch(`${JMAP_URL}/jmap/download/${encodeURIComponent(blobId)}`, {
		headers: { authorization: `Bearer ${token}` }
	});
	if (res.status === 401) {
		onUnauthorized?.();
	}
	if (!res.ok) {
		throw new JmapError(`download failed: ${res.status}`);
	}
	const blob = await res.blob();
	const url = URL.createObjectURL(blob);
	const a = document.createElement('a');
	a.href = url;
	a.download = filename;
	a.click();
	setTimeout(() => URL.revokeObjectURL(url), 0);
}

/**
 * Opens the JMAP push stream (RFC 8620 §7.3): the server emits a `state`
 * event any time this account's mail changes (new delivery, send,
 * archive/delete, from any client/tab), so callers can re-fetch instead of
 * polling. `EventSource` can't set an `Authorization` header, so the token
 * rides along as a query param -- the server accepts that as a fallback
 * specific to this endpoint (see `jmap::handlers::sse`). The browser
 * reconnects automatically on drop, re-sending the same URL. Returns a
 * cleanup function; call it on lock/unmount.
 */
export function subscribeToChanges(token: string, onChange: () => void): () => void {
	const source = new EventSource(`${JMAP_URL}/jmap/sse?token=${encodeURIComponent(token)}`);
	source.addEventListener('state', () => onChange());
	return () => source.close();
}
