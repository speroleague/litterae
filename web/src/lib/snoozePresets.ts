// Fixed preset choices for snooze/nudge times rather than a custom date
// picker -- matches this app's minimal-chrome approach (see Compose's
// plain comma-separated address fields for the same philosophy) and
// covers the common cases a personal mail client actually needs.

export interface TimePreset {
	label: string;
	/** Unix seconds. */
	at(): number;
}

function atHour(daysFromNow: number, hour: number): number {
	const d = new Date();
	d.setDate(d.getDate() + daysFromNow);
	d.setHours(hour, 0, 0, 0);
	return Math.floor(d.getTime() / 1000);
}

function nextMonday(hour: number): number {
	const d = new Date();
	const daysUntilMonday = (8 - d.getDay()) % 7 || 7;
	d.setDate(d.getDate() + daysUntilMonday);
	d.setHours(hour, 0, 0, 0);
	return Math.floor(d.getTime() / 1000);
}

export const SNOOZE_PRESETS: TimePreset[] = [
	{ label: 'Later today', at: () => Math.floor(Date.now() / 1000) + 3 * 3600 },
	{ label: 'Tomorrow morning', at: () => atHour(1, 8) },
	{ label: 'Next week', at: () => nextMonday(8) }
];

export const NUDGE_PRESETS: TimePreset[] = [
	{ label: 'In 2 days', at: () => atHour(2, 9) },
	{ label: 'In 1 week', at: () => nextMonday(9) }
];
