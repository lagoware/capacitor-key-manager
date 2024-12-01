
export interface IKeyStore {
  putCryptoKeyPair: (alias: string, keyPair: CryptoKeyPair) => Promise<void>;
  putCryptoKey: (alias: string, key: CryptoKey) => Promise<void>;
  getCryptoKeyPair: (alias: string) => Promise<CryptoKeyPair|null>;
  getCryptoKey: (alias: string) => Promise<CryptoKey|null>;  
  deleteCryptoKeyPair: (alias: string) => Promise<void>;
  deleteCryptoKey: (alias: string) => Promise<void>;
}

export type EncryptedMessage = { ciphertext: string, iv: string };
export type PasswordEncryptedRecoverableKey = EncryptedMessage & { salt: string };
export type PasswordEncryptedRecoverableKeyPair = { privateKey: PasswordEncryptedRecoverableKey, publicKey: string };
export type KeyEncryptedRecoverableKey = EncryptedMessage;
export type KeyEncryptedRecoverableKeyPair = { privateKey: KeyEncryptedRecoverableKey, publicKey: string };
export type RecoverableKey = PasswordEncryptedRecoverableKey | KeyEncryptedRecoverableKey;
export type RecoverableKeyPair = PasswordEncryptedRecoverableKeyPair | KeyEncryptedRecoverableKeyPair;

export type DerivedKeyReference = SymmetricKeyReference & { publicKeyAlias: string, info?: string };
export type SymmetricKeyReference = { keyAlias: string };
export type KeyReference = SymmetricKeyReference |
  DerivedKeyReference;

export type PasswordParams = { password: string };
export type PasswordParamsMaybeSalt = { password: string, salt?: string };
export type PasswordParamsWithSalt = { password: string, salt: string }
export type KeyWrapParams = PasswordParamsMaybeSalt | KeyReference;
export type KeyUnwrapParams = PasswordParams | KeyReference;
export type KeyUnwrapParamsWithSalt = PasswordParamsWithSalt | KeyReference;

export interface KeyManagerWebPlugin extends KeyManagerPlugin {
  useKeyStore(keyStore: IKeyStore): Promise<void>;
}

export interface KeyManagerPlugin {

  /**
   * Checks if a key or key pair exists in the key store under the provided alias.
   */
  checkAliasExists(options: { keyAlias: string }): Promise<{ aliasExists: boolean }>;

  /**
   * Generates a key that can be used for symmetric encryption / decryption.
   * The underlying key material cannot be recovered, therefore encryption / decryption will only be possible on this device.
   */
  generateKey(options: { keyAlias: string }): Promise<void>;

  /**
   * Generates a key pair that can be used for signing and verifying strings. 
   * The private key will be wrapped with the provided key reference or password.
   * The generated key pair is returned in a structure of base64-encoded strings that may later be used to recover the key into the key store. 
   */
  generateRecoverableSignatureKeyPair(options: KeyWrapParams): Promise<{ recoverableKeyPair: RecoverableKeyPair }>;
  
  /**
   * Generates a key pair that can be used for deriving key agreement secrets. 
   * The private key will be wrapped with the provided key reference or password. 
   * The generated key pair is returned in a structure of base64-encoded strings that may later be used to recover the key into the key store. 
   */
  generateRecoverableAgreementKeyPair(options: KeyWrapParams): Promise<{ recoverableKeyPair: RecoverableKeyPair}>;
  
  /**
   * Generates a key that can be used for symmetric encryption / decryption.
   * The key will be wrapped with the provided key reference or password. 
   * The generated key is returned as a structure of base64-encoded strings that may later be used to recover the key into the key store. 
   */
  generateRecoverableKey(options: KeyWrapParams): Promise<{ recoverableKey: RecoverableKey }>;
  
  /**
   * Imports a public key into the key store. The key may then be used for verifying signatures. 
   * The key is expected to be in base64-encoded spki format.
   */
  importPublicSignatureKey(options: { alias: string, publicKey: string }): Promise<void>;
  
  /**
   * Imports a public key into the key store. The key may then be used to derive key agreement secrets.
   * The key is expected to be in base64-encoded spki format.
   */
  importPublicAgreementKey(options: { alias: string, publicKey: string }): Promise<void>;

  /**
   * Re-wraps a recoverable signature key pair with a new key reference or password.
   */
  rewrapSignatureKeyPair(options: {
    recoverableKeyPair: RecoverableKeyPair,
    unwrapWith: KeyUnwrapParams,
    rewrapWith: KeyWrapParams,
  }): Promise<{ recoverableKeyPair: RecoverableKeyPair }>;
  
  /**
   * Re-wraps a recoverable agreement key pair with a new key reference or password.
   */
  rewrapAgreementKeyPair(options: {
    recoverableKeyPair: RecoverableKeyPair,
    unwrapWith: KeyUnwrapParams,
    rewrapWith: KeyWrapParams,
  }): Promise<{ recoverableKeyPair: RecoverableKeyPair }>;
  
  /**
   * Re-wraps a recoverable key with a new key reference or password.
   */
  rewrapKey(options: {
    recoverableKey: RecoverableKey|RecoverableKeyPair,
    unwrapWith: KeyUnwrapParams,
    rewrapWith: KeyWrapParams,
  }): Promise<{ recoverableKey: RecoverableKey }>;
  
  /**
   * Unwraps and imports a previously-generated recoverable key into the key store. It may then be used to encrypt and decrypt values.
   */
  recoverKey(options: { importAlias: string, recoverableKey: RecoverableKey, unwrapWith: KeyUnwrapParams }): Promise<void>;
  
  /**
   * Unwraps and imports a previously-generated recoverable agreement key pair into the key store. It may then be used to encrypt and decrypt values.
   */
  recoverAgreementKeyPair(options: { importAlias: string, recoverableKeyPair: RecoverableKeyPair, unwrapWith: KeyUnwrapParams }): Promise<void>;
  
  /**
   * Unwraps and imports a previously-generated recoverable signature key pair into the key store. It may then be used to sign and verify values.
   */
  recoverSignatureKeyPair(options: { importAlias: string, recoverableKeyPair: RecoverableKeyPair, unwrapWith: KeyUnwrapParams }): Promise<void>;
  
  /**
   * Encrypts a string with a previously generated / recovered key or key pair. The encrypted string is returned in a structure of base64-encoded strings.
   */
  encrypt(options: { encryptWith: KeyReference, cleartext: string }): Promise<{ encryptedMessage: EncryptedMessage }>;
  
  /**
   * Decrypts a string with a previously generated / recovered key or key pair.
   */
  decrypt(options: { decryptWith: KeyReference, encryptedMessage: EncryptedMessage }): Promise<{ cleartext: string }>;
  
  /**
   * Signs a string with a previously generated / recovered signature key pair.
   */
  sign(options: { keyAlias: string, cleartext: string }): Promise<{ signature: string }>;
  
  /**
   * Verifies a signature with a previously generated / recovered signature key pair or imported public key.
   */
  verify(options: { keyAlias: string, cleartext: string, signature: string }): Promise<{ isValid: boolean }>;
}