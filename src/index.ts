import { registerPlugin } from '@capacitor/core';

import type { KeyManagerPlugin } from './definitions';

const KeyManager = registerPlugin<KeyManagerPlugin>('KeyManager', {
  web: () => import('./web').then((m) => new m.KeyManagerWeb()),
});

export * from './definitions';
export { KeyManager };