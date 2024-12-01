import { WebPlugin } from '@capacitor/core';

import type { EncryptedMessage, IKeyStore, KeyManagerWebPlugin, KeyReference, KeyUnwrapParams, RecoverableKey, RecoverableKeyPair } from './definitions';
import { KeyManager } from './key-manager';

export class KeyManagerWeb extends WebPlugin implements KeyManagerWebPlugin {

  private impl : KeyManagerWebPlugin = new KeyManager;

  private keyStorePromise: Promise<void>|null = null;

  useKeyStore(keyStore: IKeyStore): Promise<void> {
    return (this.keyStorePromise = Promise.resolve(this.keyStorePromise)
      .then(() => this.impl.useKeyStore(keyStore)));
  }

  async ensureKeyStoreIsLoaded(): Promise<void> {
    if (!this.keyStorePromise) {
      const { IdbKeyStore } = await import('./idb-key-store');
      await this.useKeyStore(new IdbKeyStore);
    }
  }

  async checkAliasExists(options: { keyAlias: string; }): Promise<{ aliasExists: boolean }> {
    return this.impl.checkAliasExists(options);  
  }

  async generateKey(options: { keyAlias: string; }): Promise<void> {
    return this.impl.generateKey(options);
  }

  async generateRecoverableSignatureKeyPair(options: { password: string; salt?: string; }): Promise<{ recoverableKeyPair: RecoverableKeyPair; }> {
    await this.ensureKeyStoreIsLoaded();
    return this.impl.generateRecoverableSignatureKeyPair(options);
  }

  async generateRecoverableAgreementKeyPair(options: { password: string; salt?: string; }): Promise<{ recoverableKeyPair: RecoverableKeyPair; }> {
    await this.ensureKeyStoreIsLoaded();
    return this.impl.generateRecoverableAgreementKeyPair(options);
  }

  async generateRecoverableKey(options: { password: string; salt?: string; }): Promise<{ recoverableKey: RecoverableKey; }> {
    await this.ensureKeyStoreIsLoaded();
    return this.impl.generateRecoverableKey(options);
  }

  async rewrapSignatureKeyPair(options: { unwrapWith: KeyUnwrapParams; rewrapWith: KeyUnwrapParams; recoverableKeyPair: RecoverableKeyPair; }): Promise<{ recoverableKeyPair: RecoverableKeyPair; }> {
    await this.ensureKeyStoreIsLoaded();
    return this.impl.rewrapSignatureKeyPair(options);  
  }

  async rewrapAgreementKeyPair(options: { unwrapWith: KeyUnwrapParams; rewrapWith: KeyUnwrapParams; recoverableKeyPair: RecoverableKeyPair; }): Promise<{ recoverableKeyPair: RecoverableKeyPair; }> {
    await this.ensureKeyStoreIsLoaded();
    return this.impl.rewrapAgreementKeyPair(options);  
  }

  async rewrapKey(options: { unwrapWith: KeyUnwrapParams; rewrapWith: KeyUnwrapParams; recoverableKey: RecoverableKey; }): Promise<{ recoverableKey: RecoverableKey; }> {
    await this.ensureKeyStoreIsLoaded();
    return this.impl.rewrapKey(options);
  }

  async recoverSignatureKeyPair(options: { importAlias: string; recoverableKeyPair: RecoverableKeyPair; unwrapWith: KeyUnwrapParams; }): Promise<void> {
    await this.ensureKeyStoreIsLoaded();
    return this.impl.recoverSignatureKeyPair(options);
  }

  async recoverAgreementKeyPair(options: { importAlias: string; recoverableKeyPair: RecoverableKeyPair; unwrapWith: KeyUnwrapParams; }): Promise<void> {
    await this.ensureKeyStoreIsLoaded();
    return this.impl.recoverAgreementKeyPair(options);
  }

  async recoverKey(options: { importAlias: string; recoverableKey: RecoverableKey; unwrapWith: KeyUnwrapParams; }): Promise<void> {
    await this.ensureKeyStoreIsLoaded();
    return this.impl.recoverKey(options);
  }

  async importPublicAgreementKey(options: { alias: string; publicKey: string; }): Promise<void> {
    await this.ensureKeyStoreIsLoaded();
    return this.impl.importPublicAgreementKey(options);
  }

  async importPublicSignatureKey(options: { alias: string; publicKey: string; }): Promise<void> {
    await this.ensureKeyStoreIsLoaded();
    return this.impl.importPublicSignatureKey(options);
  }

  async encrypt(options: { encryptWith: KeyReference; cleartext: string; }): Promise<{ encryptedMessage: EncryptedMessage; }> {
    await this.ensureKeyStoreIsLoaded();
    return this.impl.encrypt(options);
  }

  async decrypt(options: { decryptWith: KeyReference; encryptedMessage: EncryptedMessage; }): Promise<{ cleartext: string; }> {
    await this.ensureKeyStoreIsLoaded();
    return this.impl.decrypt(options);
  }

  async sign(options: { keyAlias: string; cleartext: string; }): Promise<{ signature: string; }> {
    await this.ensureKeyStoreIsLoaded();
    return this.impl.sign(options);
  }

  async verify(options: { keyAlias: string; cleartext: string; signature: string; }): Promise<{ isValid: boolean; }> {
    await this.ensureKeyStoreIsLoaded();
    return this.impl.verify(options);
  }

}
