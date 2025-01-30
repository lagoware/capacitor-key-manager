import { WebPlugin } from '@capacitor/core';

import type { EncryptedMessage, KeyManagerPlugin, KeyReference, KeyUnwrapParams, RecoverableKey, RecoverableKeyPair } from './definitions';
import { KeyManager } from './key-manager';
import { IdbKeyStore } from './idb-key-store';

export class KeyManagerWeb extends WebPlugin implements KeyManagerPlugin {

  private impl : KeyManager = new KeyManager;

  constructor() {
    super();
    this.impl.useKeyStore(new IdbKeyStore);
  }

  async checkAliasExists(options: { keyAlias: string; }): Promise<{ aliasExists: boolean }> {
    return this.impl.checkAliasExists(options);  
  }

  async generateKey(options: { keyAlias: string; }): Promise<void> {
    return this.impl.generateKey(options);
  }

  async generateRecoverableSignatureKeyPair(options: { password: string; salt?: string; }): Promise<{ recoverableKeyPair: RecoverableKeyPair; }> {
    return this.impl.generateRecoverableSignatureKeyPair(options);
  }

  async generateRecoverableAgreementKeyPair(options: { password: string; salt?: string; }): Promise<{ recoverableKeyPair: RecoverableKeyPair; }> {
    return this.impl.generateRecoverableAgreementKeyPair(options);
  }

  async generateRecoverableKey(options: { password: string; salt?: string; }): Promise<{ recoverableKey: RecoverableKey; }> {
    return this.impl.generateRecoverableKey(options);
  }

  async rewrapSignatureKeyPair(options: { unwrapWith: KeyUnwrapParams; rewrapWith: KeyUnwrapParams; recoverableKeyPair: RecoverableKeyPair; }): Promise<{ recoverableKeyPair: RecoverableKeyPair; }> {
    return this.impl.rewrapSignatureKeyPair(options);  
  }

  async rewrapAgreementKeyPair(options: { unwrapWith: KeyUnwrapParams; rewrapWith: KeyUnwrapParams; recoverableKeyPair: RecoverableKeyPair; }): Promise<{ recoverableKeyPair: RecoverableKeyPair; }> {
    return this.impl.rewrapAgreementKeyPair(options);  
  }

  async rewrapKey(options: { unwrapWith: KeyUnwrapParams; rewrapWith: KeyUnwrapParams; recoverableKey: RecoverableKey; }): Promise<{ recoverableKey: RecoverableKey; }> {
    return this.impl.rewrapKey(options);
  }

  async recoverSignatureKeyPair(options: { importAlias: string; recoverableKeyPair: RecoverableKeyPair; unwrapWith: KeyUnwrapParams; }): Promise<void> {
    return this.impl.recoverSignatureKeyPair(options);
  }

  async recoverAgreementKeyPair(options: { importAlias: string; recoverableKeyPair: RecoverableKeyPair; unwrapWith: KeyUnwrapParams; }): Promise<void> {
    return this.impl.recoverAgreementKeyPair(options);
  }

  async recoverKey(options: { importAlias: string; recoverableKey: RecoverableKey; unwrapWith: KeyUnwrapParams; }): Promise<void> {
    return this.impl.recoverKey(options);
  }

  async importPublicAgreementKey(options: { alias: string; publicKey: string; }): Promise<void> {
    return this.impl.importPublicAgreementKey(options);
  }

  async importPublicSignatureKey(options: { alias: string; publicKey: string; }): Promise<void> {
    return this.impl.importPublicSignatureKey(options);
  }

  async encrypt(options: { encryptWith: KeyReference; cleartext: string; }): Promise<{ encryptedMessage: EncryptedMessage; }> {
    return this.impl.encrypt(options);
  }

  async decrypt(options: { decryptWith: KeyReference; encryptedMessage: EncryptedMessage; }): Promise<{ cleartext: string; }> {
    return this.impl.decrypt(options);
  }

  async sign(options: { keyAlias: string; cleartext: string; }): Promise<{ signature: string; }> {
    return this.impl.sign(options);
  }

  async verify(options: { keyAlias: string; cleartext: string; signature: string; }): Promise<{ isValid: boolean; }> {
    return this.impl.verify(options);
  }

}
