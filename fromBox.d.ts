export function hideFrom(identityPubB64: string, fromId: string): Promise<string>;
export function showFrom(identityPrivB64: string, box: string): Promise<string>;
export function hourStamp(ms?: number): number;
