import type { KeyManagerPlugin } from './definitions';
import { registerPlugin } from '@capacitor/core';

const KeyManager = registerPlugin<KeyManagerPlugin>('KeyManager', {
  web: () => import('./web').then((m) => new m.KeyManagerWeb()),
});

export * from './definitions';
export { KeyManager };