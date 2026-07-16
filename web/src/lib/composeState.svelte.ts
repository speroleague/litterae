// Shared modal state so "New Message" (mail list), "Reply" (message view),
// and "resume editing" (clicking a Drafts row) can all open the same
// compose overlay without threading props through every route.

export interface PendingAttachment {
	/** A `u{id}` blobId from `uploadAttachment` -- the only shape a
	 * compose request accepts (referencing an existing message's own
	 * attachment isn't supported, only fresh uploads). */
	blobId: string;
	name: string;
	size: number;
}

class ComposeState {
	open = $state(false);
	/** Set only when resuming an existing draft -- Send/Save Draft then
	 * replace this row (destroy + recreate) instead of creating a new one. */
	draftId = $state<string | null>(null);
	/** JMAP id of the message being replied to, carried through to the
	 * server so it can thread the reply properly. */
	inReplyTo = $state<string | null>(null);
	to = $state('');
	cc = $state('');
	subject = $state('');
	bodyText = $state('');
	attachments = $state<PendingAttachment[]>([]);
}

export const composeState = new ComposeState();

/** Cached from `Identity/get` after unlock (see mail/+layout.svelte) so
 * openNewMessage/openReply can insert it synchronously -- it's plain text
 * the user types into and can edit/remove, same as any mail client's
 * signature, not something the server appends at send time. */
const identityState = $state({ signature: '' });

export function setSignature(text: string) {
	identityState.signature = text;
}

function signatureBlock(): string {
	return identityState.signature.trim() ? `\n\n-- \n${identityState.signature}` : '';
}

function reset() {
	composeState.draftId = null;
	composeState.inReplyTo = null;
	composeState.to = '';
	composeState.cc = '';
	composeState.subject = '';
	composeState.bodyText = '';
	composeState.attachments = [];
}

export function addAttachment(attachment: PendingAttachment) {
	composeState.attachments = [...composeState.attachments, attachment];
}

export function removeAttachment(blobId: string) {
	composeState.attachments = composeState.attachments.filter((a) => a.blobId !== blobId);
}

export function openNewMessage() {
	reset();
	composeState.bodyText = signatureBlock();
	composeState.open = true;
}

export function openReply(opts: { to: string; subject: string; inReplyTo: string }) {
	reset();
	composeState.to = opts.to;
	composeState.subject = opts.subject.toLowerCase().startsWith('re:') ? opts.subject : `Re: ${opts.subject}`;
	composeState.inReplyTo = opts.inReplyTo;
	composeState.bodyText = signatureBlock();
	composeState.open = true;
}

export function openDraft(opts: { draftId: string; to: string; cc: string; subject: string; bodyText: string }) {
	reset();
	composeState.draftId = opts.draftId;
	composeState.to = opts.to;
	composeState.cc = opts.cc;
	composeState.subject = opts.subject;
	composeState.bodyText = opts.bodyText;
	composeState.open = true;
}

export function closeCompose() {
	composeState.open = false;
	reset();
}

/** "alice@x.com, Bob <bob@y.com>" -> [{email, name?}, ...]. Same loose
 * parsing on both to/cc fields, plain comma-separated, no validation
 * beyond "has an @" -- matches the rest of this app's minimal-chrome
 * approach rather than building a full address-chip input for v1. */
export function parseAddressList(text: string): { name?: string; email: string }[] {
	return text
		.split(',')
		.map((part) => part.trim())
		.filter((part) => part.length > 0)
		.map((part) => {
			const match = part.match(/^(.*)<(.+)>$/);
			if (match) {
				const name = match[1].trim();
				return { name: name || undefined, email: match[2].trim() };
			}
			return { email: part };
		});
}
