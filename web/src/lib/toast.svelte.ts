// Unified error/notification surface for the mail app. Replaces the old
// per-component `let error = $state(...)` + inline red `<p>` pattern: those
// were easy to miss, and in a couple of spots (mailbox list, message view)
// an action failure reused the same state slot as the page's initial-load
// error, so failing to e.g. snooze a message replaced the entire message
// view with an error line. A toast can't clobber content that's already on
// screen.
//
// Initial-load failures (the mailbox list or a message failing to load at
// all) are deliberately NOT routed through here -- those stay as persistent
// inline empty/error states, since there's no content for a transient toast
// to sit on top of and the user needs the explanation to stick around.

export type ToastVariant = 'error' | 'success';

export interface ToastItem {
	id: number;
	message: string;
	variant: ToastVariant;
}

const DEFAULT_DURATION_MS = 5000;

class ToastState {
	items = $state<ToastItem[]>([]);
}

export const toastState = new ToastState();

let nextId = 1;

export function showToast(message: string, variant: ToastVariant = 'error', durationMs = DEFAULT_DURATION_MS) {
	const id = nextId++;
	toastState.items.push({ id, message, variant });
	setTimeout(() => dismissToast(id), durationMs);
	return id;
}

export function dismissToast(id: number) {
	const index = toastState.items.findIndex((item) => item.id === id);
	if (index !== -1) toastState.items.splice(index, 1);
}
