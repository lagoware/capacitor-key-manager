# @lagoware/capacitor-key-manager

Utilize and store encryption and signing keys.

* [x] Android
* [x] Web
* [ ] iOS (PRs welcome)

## Key Storage

### Android

Keys are stored in the [Android Key Store](https://developer.android.com/privacy-and-security/keystore).

### Web

Keys are stored as non-extractable [Web Crypto](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) keys in an [IndexedDB](https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API) database. Please note that your keys may be at risk of eviction by the browser unless your app successfully requests [persistent storage](https://web.dev/articles/persistent-storage).

## Install

```bash
npm install @lagoware/capacitor-key-manager
npx cap sync
```

## API

<docgen-index>

* [`generateKey(...)`](#generatekey)
* [`generateRecoverableSignatureKeyPair(...)`](#generaterecoverablesignaturekeypair)
* [`generateRecoverableAgreementKeyPair(...)`](#generaterecoverableagreementkeypair)
* [`generateRecoverableKey(...)`](#generaterecoverablekey)
* [`importPublicSignatureKey(...)`](#importpublicsignaturekey)
* [`importPublicAgreementKey(...)`](#importpublicagreementkey)
* [`reWrapSignatureKeyPair(...)`](#rewrapsignaturekeypair)
* [`reWrapAgreementKeyPair(...)`](#rewrapagreementkeypair)
* [`reWrapKey(...)`](#rewrapkey)
* [`recoverKey(...)`](#recoverkey)
* [`recoverSignatureKeyPair(...)`](#recoversignaturekeypair)
* [`recoverAgreementKeyPair(...)`](#recoveragreementkeypair)
* [`encrypt(...)`](#encrypt)
* [`decrypt(...)`](#decrypt)
* [`encryptWithAgreedKey(...)`](#encryptwithagreedkey)
* [`decryptWithAgreedKey(...)`](#decryptwithagreedkey)
* [`sign(...)`](#sign)
* [`verify(...)`](#verify)
* [`checkAliasExists(...)`](#checkaliasexists)
* [Type Aliases](#type-aliases)

</docgen-index>

<docgen-api>
<!--Update the source file JSDoc comments and rerun docgen to update the docs below-->

### generateKey(...)

```typescript
generateKey(options: { keyAlias: string; }) => Promise<void>
```

Generates a key that can be used for symmetrical encryption / decryption.
The underlying key material cannot be recovered, therefore encryption / decryption will only be possible on this device.

| Param         | Type                               |
| ------------- | ---------------------------------- |
| **`options`** | <code>{ keyAlias: string; }</code> |

--------------------


### generateRecoverableSignatureKeyPair(...)

```typescript
generateRecoverableSignatureKeyPair(options: { password: string; salt?: string; }) => Promise<{ recoverableKeyPair: RecoverableKeyPair; }>
```

Generates a key pair that can be used for signing and verifying strings. 
The private key will be encrypted with the provided password and if provided, (base64-encoded) salt (otherwise a random salt will be generated). 
The generated key pair is returned in a structure of base64-encoded strings that may later be used to recover the key into the key store.

| Param         | Type                                              |
| ------------- | ------------------------------------------------- |
| **`options`** | <code>{ password: string; salt?: string; }</code> |

**Returns:** <code>Promise&lt;{ recoverableKeyPair: <a href="#recoverablekeypair">RecoverableKeyPair</a>; }&gt;</code>

--------------------


### generateRecoverableAgreementKeyPair(...)

```typescript
generateRecoverableAgreementKeyPair(options: { password: string; salt?: string; }) => Promise<{ recoverableKeyPair: RecoverableKeyPair; }>
```

Generates a key pair that can be used for deriving key agreement secrets. 
The private key will be encrypted with the provided password and if provided, (base64-encoded) salt (otherwise a random salt will be generated). 
The generated key pair is returned in a structure of base64-encoded strings that may later be used to recover the key into the key store.

| Param         | Type                                              |
| ------------- | ------------------------------------------------- |
| **`options`** | <code>{ password: string; salt?: string; }</code> |

**Returns:** <code>Promise&lt;{ recoverableKeyPair: <a href="#recoverablekeypair">RecoverableKeyPair</a>; }&gt;</code>

--------------------


### generateRecoverableKey(...)

```typescript
generateRecoverableKey(options: { password: string; salt?: string; }) => Promise<{ recoverableKey: RecoverableKey; }>
```

Generates a key that can be used for symmetrical encryption / decryption.
The key will be encrypted with the provided password and if provided, (base64-encoded) salt (otherwise a random salt will be generated). 
The generated key is returned as a structure of base64-encoded strings that may later be used to recover the key into the key store.

| Param         | Type                                              |
| ------------- | ------------------------------------------------- |
| **`options`** | <code>{ password: string; salt?: string; }</code> |

**Returns:** <code>Promise&lt;{ recoverableKey: <a href="#recoverablekey">RecoverableKey</a>; }&gt;</code>

--------------------


### importPublicSignatureKey(...)

```typescript
importPublicSignatureKey(options: { alias: string; publicKey: string; }) => Promise<void>
```

Imports a public key into the key store. The key may then be used for verifying signatures. 
The key is expected to be in base64-encoded spki format.

| Param         | Type                                               |
| ------------- | -------------------------------------------------- |
| **`options`** | <code>{ alias: string; publicKey: string; }</code> |

--------------------


### importPublicAgreementKey(...)

```typescript
importPublicAgreementKey(options: { alias: string; publicKey: string; }) => Promise<void>
```

Imports a public key into the key store. The key may then be used to derive key agreement secrets.
The key is expected to be in base64-encoded spki format.

| Param         | Type                                               |
| ------------- | -------------------------------------------------- |
| **`options`** | <code>{ alias: string; publicKey: string; }</code> |

--------------------


### reWrapSignatureKeyPair(...)

```typescript
reWrapSignatureKeyPair(options: { currentPassword: string; newPassword: string; newSalt?: string; recoverableKeyPair: RecoverableKeyPair; }) => Promise<{ recoverableKeyPair: RecoverableKeyPair; }>
```

Re-wraps a recoverable signature key pair with a new password.

| Param         | Type                                                                                                                                                       |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`options`** | <code>{ currentPassword: string; newPassword: string; newSalt?: string; recoverableKeyPair: <a href="#recoverablekeypair">RecoverableKeyPair</a>; }</code> |

**Returns:** <code>Promise&lt;{ recoverableKeyPair: <a href="#recoverablekeypair">RecoverableKeyPair</a>; }&gt;</code>

--------------------


### reWrapAgreementKeyPair(...)

```typescript
reWrapAgreementKeyPair(options: { currentPassword: string; newPassword: string; newSalt?: string; recoverableKeyPair: RecoverableKeyPair; }) => Promise<{ recoverableKeyPair: RecoverableKeyPair; }>
```

Re-wraps a recoverable agreement key pair with a new password.

| Param         | Type                                                                                                                                                       |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`options`** | <code>{ currentPassword: string; newPassword: string; newSalt?: string; recoverableKeyPair: <a href="#recoverablekeypair">RecoverableKeyPair</a>; }</code> |

**Returns:** <code>Promise&lt;{ recoverableKeyPair: <a href="#recoverablekeypair">RecoverableKeyPair</a>; }&gt;</code>

--------------------


### reWrapKey(...)

```typescript
reWrapKey(options: { currentPassword: string; newPassword: string; newSalt?: string; recoverableKey: RecoverableKey; }) => Promise<{ recoverableKey: RecoverableKey; }>
```

Re-wraps a recoverable key with a new password.

| Param         | Type                                                                                                                                           |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| **`options`** | <code>{ currentPassword: string; newPassword: string; newSalt?: string; recoverableKey: <a href="#recoverablekey">RecoverableKey</a>; }</code> |

**Returns:** <code>Promise&lt;{ recoverableKey: <a href="#recoverablekey">RecoverableKey</a>; }&gt;</code>

--------------------


### recoverKey(...)

```typescript
recoverKey(options: { alias: string; recoverableKey: RecoverableKey; password: string; }) => Promise<void>
```

Imports a previously-generated recoverable key into the key store. If the provided password matches the password used when
the key was generated, it will be decrypted and saved into the key store. It may then be used to encrypt and decrypt values.

| Param         | Type                                                                                                            |
| ------------- | --------------------------------------------------------------------------------------------------------------- |
| **`options`** | <code>{ alias: string; recoverableKey: <a href="#recoverablekey">RecoverableKey</a>; password: string; }</code> |

--------------------


### recoverSignatureKeyPair(...)

```typescript
recoverSignatureKeyPair(options: { alias: string; recoverableKeyPair: RecoverableKeyPair; password: string; }) => Promise<void>
```

Imports a previously-generated recoverable signature key pair into the key store. If the provided password matches the password used when
the key pair was generated, it will be decrypted and saved into the key store. It may then be used to sign and verify signatures.

| Param         | Type                                                                                                                        |
| ------------- | --------------------------------------------------------------------------------------------------------------------------- |
| **`options`** | <code>{ alias: string; recoverableKeyPair: <a href="#recoverablekeypair">RecoverableKeyPair</a>; password: string; }</code> |

--------------------


### recoverAgreementKeyPair(...)

```typescript
recoverAgreementKeyPair(options: { alias: string; recoverableKeyPair: RecoverableKeyPair; password: string; }) => Promise<void>
```

Imports a previously-generated recoverable agreement key pair into the key store. If the provided password matches the password used when
the key pair was generated, it will be decrypted and saved into the key store. It may then be used to derive key agreement secrets.

| Param         | Type                                                                                                                        |
| ------------- | --------------------------------------------------------------------------------------------------------------------------- |
| **`options`** | <code>{ alias: string; recoverableKeyPair: <a href="#recoverablekeypair">RecoverableKeyPair</a>; password: string; }</code> |

--------------------


### encrypt(...)

```typescript
encrypt(options: { keyAlias: string; cleartext: string; }) => Promise<{ encryptedMessage: EncryptedMessage; }>
```

Encrypts a string with a previously generated / recovered key. The encrypted string is returned in a structure of base64-encoded strings.

| Param         | Type                                                  |
| ------------- | ----------------------------------------------------- |
| **`options`** | <code>{ keyAlias: string; cleartext: string; }</code> |

**Returns:** <code>Promise&lt;{ encryptedMessage: <a href="#encryptedmessage">EncryptedMessage</a>; }&gt;</code>

--------------------


### decrypt(...)

```typescript
decrypt(options: { keyAlias: string; encryptedMessage: EncryptedMessage; }) => Promise<{ cleartext: string; }>
```

Decrypts a string with a previously generated / recovered key.

| Param         | Type                                                                                                   |
| ------------- | ------------------------------------------------------------------------------------------------------ |
| **`options`** | <code>{ keyAlias: string; encryptedMessage: <a href="#encryptedmessage">EncryptedMessage</a>; }</code> |

**Returns:** <code>Promise&lt;{ cleartext: string; }&gt;</code>

--------------------


### encryptWithAgreedKey(...)

```typescript
encryptWithAgreedKey(options: { privateKeyAlias: string; publicKeyAlias: string; cleartext: string; info?: string; }) => Promise<{ encryptedMessage: EncryptedMessage; }>
```

Encrypts a string with a key derived from the provided private and public agreement keys. 
If info parameter is provided, it will be used to further derive the key before encryption.

| Param         | Type                                                                                                |
| ------------- | --------------------------------------------------------------------------------------------------- |
| **`options`** | <code>{ privateKeyAlias: string; publicKeyAlias: string; cleartext: string; info?: string; }</code> |

**Returns:** <code>Promise&lt;{ encryptedMessage: <a href="#encryptedmessage">EncryptedMessage</a>; }&gt;</code>

--------------------


### decryptWithAgreedKey(...)

```typescript
decryptWithAgreedKey(options: { privateKeyAlias: string; publicKeyAlias: string; encryptedMessage: EncryptedMessage; info?: string; }) => Promise<{ cleartext: string; }>
```

Decrypts a string with a key derived from the provided private and public agreement keys. 
If info parameter is provided, it will be used to further derive the key before decryption.

| Param         | Type                                                                                                                                                 |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`options`** | <code>{ privateKeyAlias: string; publicKeyAlias: string; encryptedMessage: <a href="#encryptedmessage">EncryptedMessage</a>; info?: string; }</code> |

**Returns:** <code>Promise&lt;{ cleartext: string; }&gt;</code>

--------------------


### sign(...)

```typescript
sign(options: { keyAlias: string; cleartext: string; }) => Promise<{ signature: string; }>
```

Signs a string with a previously generated / recovered signature key pair.

| Param         | Type                                                  |
| ------------- | ----------------------------------------------------- |
| **`options`** | <code>{ keyAlias: string; cleartext: string; }</code> |

**Returns:** <code>Promise&lt;{ signature: string; }&gt;</code>

--------------------


### verify(...)

```typescript
verify(options: { keyAlias: string; cleartext: string; signature: string; }) => Promise<{ isValid: boolean; }>
```

Verifies a signature with a previously generated / recovered signature key pair or imported public key.

| Param         | Type                                                                     |
| ------------- | ------------------------------------------------------------------------ |
| **`options`** | <code>{ keyAlias: string; cleartext: string; signature: string; }</code> |

**Returns:** <code>Promise&lt;{ isValid: boolean; }&gt;</code>

--------------------


### checkAliasExists(...)

```typescript
checkAliasExists(options: { keyAlias: string; }) => Promise<{ aliasExists: boolean; }>
```

Checks if a key or key pair exists under the provided alias.

| Param         | Type                               |
| ------------- | ---------------------------------- |
| **`options`** | <code>{ keyAlias: string; }</code> |

**Returns:** <code>Promise&lt;{ aliasExists: boolean; }&gt;</code>

--------------------


### Type Aliases


#### RecoverableKeyPair

<code>{ privateKey: <a href="#recoverablekey">RecoverableKey</a>, publicKey: string }</code>


#### RecoverableKey

<code><a href="#encryptedmessage">EncryptedMessage</a> & { salt: string }</code>


#### EncryptedMessage

<code>{ ciphertext: string, iv: string }</code>

</docgen-api>
