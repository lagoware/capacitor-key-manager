
export interface IKeyStore {
  putCryptoKeyPair: (alias: string, keyPair: CryptoKeyPair) => Promise<void>;
  putCryptoKey: (alias: string, key: CryptoKey) => Promise<void>;
  getCryptoKeyPair: (alias: string) => Promise<CryptoKeyPair|null>;
  getCryptoKey: (alias: string) => Promise<CryptoKey|null>;  
  deleteCryptoKeyPair: (alias: string) => Promise<void>;
  deleteCryptoKey: (alias: string) => Promise<void>;
}

export type RecoverableKeyPair = { privateKey: RecoverableKey, publicKey: string };
export type RecoverableKey = EncryptedMessage & { salt: string };
export type EncryptedMessage = { ciphertext: string, iv: string };

export interface KeyManagerWebPlugin extends KeyManagerPlugin {
  useKeyStore(keyStore: IKeyStore): Promise<void>;
}

export interface KeyManagerPlugin {

  /**
   * Checks if a key or key pair exists in the key store under the provided alias.
   */
  checkAliasExists(options: { keyAlias: string }): Promise<{ aliasExists: boolean }>;

  /**
   * Generates a key that can be used for symmetrical encryption / decryption.
   * The underlying key material cannot be recovered, therefore encryption / decryption will only be possible on this device.
   */
  generateKey(options: { keyAlias: string }): Promise<void>;

  /**
   * Generates a key pair that can be used for signing and verifying strings. 
   * The private key will be encrypted with the provided password and if provided, (base64-encoded) salt (otherwise a random salt will be generated). 
   * The generated key pair is returned in a structure of base64-encoded strings that may later be used to recover the key into the key store. 
   */
  generateRecoverableSignatureKeyPair(options: { password: string, salt?: string }): Promise<{ recoverableKeyPair: RecoverableKeyPair}>;
  
  /**
   * Generates a key pair that can be used for deriving key agreement secrets. 
   * The private key will be encrypted with the provided password and if provided, (base64-encoded) salt (otherwise a random salt will be generated). 
   * The generated key pair is returned in a structure of base64-encoded strings that may later be used to recover the key into the key store. 
   */
  generateRecoverableAgreementKeyPair(options: { password: string, salt?: string }): Promise<{ recoverableKeyPair: RecoverableKeyPair}>;
  
  /**
   * Generates a key that can be used for symmetrical encryption / decryption.
   * The key will be encrypted with the provided password and if provided, (base64-encoded) salt (otherwise a random salt will be generated). 
   * The generated key is returned as a structure of base64-encoded strings that may later be used to recover the key into the key store. 
   */
  generateRecoverableKey(options: { password: string, salt?: string }): Promise<{ recoverableKey: RecoverableKey }>;
  
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
   * Re-wraps a recoverable signature key pair with a new password.
   */
  reWrapSignatureKeyPair(options: { currentPassword: string, newPassword: string, newSalt?: string, recoverableKeyPair: RecoverableKeyPair }): Promise<{ recoverableKeyPair: RecoverableKeyPair }>;
  
  /**
   * Re-wraps a recoverable agreement key pair with a new password.
   */
  reWrapAgreementKeyPair(options: { currentPassword: string, newPassword: string, newSalt?: string, recoverableKeyPair: RecoverableKeyPair }): Promise<{ recoverableKeyPair: RecoverableKeyPair }>;
  
  /**
   * Re-wraps a recoverable key with a new password.
   */
  reWrapKey(options: { currentPassword: string, newPassword: string, newSalt?: string, recoverableKey: RecoverableKey }): Promise<{ recoverableKey: RecoverableKey }>;
  
  /**
   * Imports a previously-generated recoverable key into the key store. If the provided password matches the password used when
   * the key was generated, it will be decrypted and saved into the key store. It may then be used to encrypt and decrypt values.
   */
  recoverKey(options: { alias: string, recoverableKey: RecoverableKey, password: string }): Promise<void>;
  
  /**
   * Imports a previously-generated recoverable signature key pair into the key store. If the provided password matches the password used when
   * the key pair was generated, it will be decrypted and saved into the key store. It may then be used to sign and verify signatures.
   */
  recoverSignatureKeyPair(options: { alias: string, recoverableKeyPair: RecoverableKeyPair, password: string }): Promise<void>;

  /**
   * Imports a previously-generated recoverable agreement key pair into the key store. If the provided password matches the password used when
   * the key pair was generated, it will be decrypted and saved into the key store. It may then be used to derive key agreement secrets.
   */
  recoverAgreementKeyPair(options: { alias: string, recoverableKeyPair: RecoverableKeyPair, password: string }): Promise<void>;
  
  /**
   * Encrypts a string with a previously generated / recovered key. The encrypted string is returned in a structure of base64-encoded strings.
   */
  encrypt(options: { keyAlias: string, cleartext: string }): Promise<{ encryptedMessage: EncryptedMessage }>;
  
  /**
   * Decrypts a string with a previously generated / recovered key.
   */
  decrypt(options: { keyAlias: string, encryptedMessage: EncryptedMessage }): Promise<{ cleartext: string }>;
  
  /**
   * Encrypts a string with a key derived from the provided private and public agreement keys. 
   * If info parameter is provided, it will be used to further derive the key before encryption.
   */
  encryptWithAgreedKey(options: { privateKeyAlias: string, publicKeyAlias: string, cleartext: string, info?: string }): Promise<{ encryptedMessage: EncryptedMessage }>;
  
  /**
   * Decrypts a string with a key derived from the provided private and public agreement keys. 
   * If info parameter is provided, it will be used to further derive the key before decryption.
   */
  decryptWithAgreedKey(options: { privateKeyAlias: string, publicKeyAlias: string, encryptedMessage: EncryptedMessage, info?: string }): Promise<{ cleartext: string }>;

  /**
   * Signs a string with a previously generated / recovered signature key pair.
   */
  sign(options: { keyAlias: string, cleartext: string }): Promise<{ signature: string }>;
  
  /**
   * Verifies a signature with a previously generated / recovered signature key pair or imported public key.
   */
  verify(options: { keyAlias: string, cleartext: string, signature: string }): Promise<{ isValid: boolean }>;

}