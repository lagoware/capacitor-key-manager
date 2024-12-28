# @lagoware/capacitor-key-manager

Utilize and store encryption and signing keys.

* [x] Android
* [x] Web
* [ ] iOS (PRs welcome)

## Key Storage

### Android

Keys are stored in the [Android Key Store](https://developer.android.com/privacy-and-security/keystore).

Please note the following caveats:

    - Agreement key operations are currently only supported on Android 13+
    - The highest level of security key storage (StrongBox) is attempted, falling back to TEE and / or software-based encryption.
    - Even for devices that do support hardware-based key storage, agreement keys are typically not supported. This means agreement keys will almost always be stored using software-based encryption.

### Web

Keys are stored as non-extractable [Web Crypto](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) keys in an [IndexedDB](https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API) database. Please note that your keys may be at risk of eviction by the browser unless your app successfully requests [persistent storage](https://web.dev/articles/persistent-storage).

## Install

```bash
npm install @lagoware/capacitor-key-manager
npx cap sync
```

## API

<docgen-index>

* [`checkAliasExists(...)`](#checkaliasexists)
* [`generateKey(...)`](#generatekey)
* [`generateRecoverableSignatureKeyPair(...)`](#generaterecoverablesignaturekeypair)
* [`generateRecoverableAgreementKeyPair(...)`](#generaterecoverableagreementkeypair)
* [`generateRecoverableKey(...)`](#generaterecoverablekey)
* [`importPublicSignatureKey(...)`](#importpublicsignaturekey)
* [`importPublicAgreementKey(...)`](#importpublicagreementkey)
* [`rewrapSignatureKeyPair(...)`](#rewrapsignaturekeypair)
* [`rewrapAgreementKeyPair(...)`](#rewrapagreementkeypair)
* [`rewrapKey(...)`](#rewrapkey)
* [`recoverKey(...)`](#recoverkey)
* [`recoverAgreementKeyPair(...)`](#recoveragreementkeypair)
* [`recoverSignatureKeyPair(...)`](#recoversignaturekeypair)
* [`encrypt(...)`](#encrypt)
* [`decrypt(...)`](#decrypt)
* [`sign(...)`](#sign)
* [`verify(...)`](#verify)
* [Type Aliases](#type-aliases)

</docgen-index>

<docgen-api>
<!--Update the source file JSDoc comments and rerun docgen to update the docs below-->

### checkAliasExists(...)

```typescript
checkAliasExists(options: { keyAlias: string; }) => Promise<{ aliasExists: boolean; }>
```

Checks if a key or key pair exists in the key store under the provided alias.

| Param         | Type                               |
| ------------- | ---------------------------------- |
| **`options`** | <code>{ keyAlias: string; }</code> |

**Returns:** <code>Promise&lt;{ aliasExists: boolean; }&gt;</code>

--------------------


### generateKey(...)

```typescript
generateKey(options: { keyAlias: string; }) => Promise<void>
```

Generates a key that can be used for symmetric encryption / decryption.
The underlying key material cannot be recovered, therefore encryption / decryption will only be possible on this device.

| Param         | Type                               |
| ------------- | ---------------------------------- |
| **`options`** | <code>{ keyAlias: string; }</code> |

--------------------


### generateRecoverableSignatureKeyPair(...)

```typescript
generateRecoverableSignatureKeyPair(options: KeyWrapParams) => Promise<{ recoverableKeyPair: RecoverableKeyPair; }>
```

Generates a key pair that can be used for signing and verifying strings. 
The private key will be wrapped with the provided key reference or password.
The generated key pair is returned in a structure of base64-encoded strings that may later be used to recover the key into the key store.

| Param         | Type                                                    |
| ------------- | ------------------------------------------------------- |
| **`options`** | <code><a href="#keywrapparams">KeyWrapParams</a></code> |

**Returns:** <code>Promise&lt;{ recoverableKeyPair: <a href="#recoverablekeypair">RecoverableKeyPair</a>; }&gt;</code>

--------------------


### generateRecoverableAgreementKeyPair(...)

```typescript
generateRecoverableAgreementKeyPair(options: KeyWrapParams) => Promise<{ recoverableKeyPair: RecoverableKeyPair; }>
```

Generates a key pair that can be used for deriving key agreement secrets. 
The private key will be wrapped with the provided key reference or password. 
The generated key pair is returned in a structure of base64-encoded strings that may later be used to recover the key into the key store.

| Param         | Type                                                    |
| ------------- | ------------------------------------------------------- |
| **`options`** | <code><a href="#keywrapparams">KeyWrapParams</a></code> |

**Returns:** <code>Promise&lt;{ recoverableKeyPair: <a href="#recoverablekeypair">RecoverableKeyPair</a>; }&gt;</code>

--------------------


### generateRecoverableKey(...)

```typescript
generateRecoverableKey(options: KeyWrapParams) => Promise<{ recoverableKey: RecoverableKey; }>
```

Generates a key that can be used for symmetric encryption / decryption.
The key will be wrapped with the provided key reference or password. 
The generated key is returned as a structure of base64-encoded strings that may later be used to recover the key into the key store.

| Param         | Type                                                    |
| ------------- | ------------------------------------------------------- |
| **`options`** | <code><a href="#keywrapparams">KeyWrapParams</a></code> |

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


### rewrapSignatureKeyPair(...)

```typescript
rewrapSignatureKeyPair(options: { recoverableKeyPair: RecoverableKeyPair; unwrapWith: KeyUnwrapParams; rewrapWith: KeyWrapParams; }) => Promise<{ recoverableKeyPair: RecoverableKeyPair; }>
```

Re-wraps a recoverable signature key pair with a new key reference or password.

| Param         | Type                                                                                                                                                                                                           |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`options`** | <code>{ recoverableKeyPair: <a href="#recoverablekeypair">RecoverableKeyPair</a>; unwrapWith: <a href="#keyunwrapparams">KeyUnwrapParams</a>; rewrapWith: <a href="#keywrapparams">KeyWrapParams</a>; }</code> |

**Returns:** <code>Promise&lt;{ recoverableKeyPair: <a href="#recoverablekeypair">RecoverableKeyPair</a>; }&gt;</code>

--------------------


### rewrapAgreementKeyPair(...)

```typescript
rewrapAgreementKeyPair(options: { recoverableKeyPair: RecoverableKeyPair; unwrapWith: KeyUnwrapParams; rewrapWith: KeyWrapParams; }) => Promise<{ recoverableKeyPair: RecoverableKeyPair; }>
```

Re-wraps a recoverable agreement key pair with a new key reference or password.

| Param         | Type                                                                                                                                                                                                           |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`options`** | <code>{ recoverableKeyPair: <a href="#recoverablekeypair">RecoverableKeyPair</a>; unwrapWith: <a href="#keyunwrapparams">KeyUnwrapParams</a>; rewrapWith: <a href="#keywrapparams">KeyWrapParams</a>; }</code> |

**Returns:** <code>Promise&lt;{ recoverableKeyPair: <a href="#recoverablekeypair">RecoverableKeyPair</a>; }&gt;</code>

--------------------


### rewrapKey(...)

```typescript
rewrapKey(options: { recoverableKey: RecoverableKey | RecoverableKeyPair; unwrapWith: KeyUnwrapParams; rewrapWith: KeyWrapParams; }) => Promise<{ recoverableKey: RecoverableKey; }>
```

Re-wraps a recoverable key with a new key reference or password.

| Param         | Type                                                                                                                                                                                                                                                       |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`options`** | <code>{ recoverableKey: <a href="#recoverablekeypair">RecoverableKeyPair</a> \| <a href="#recoverablekey">RecoverableKey</a>; unwrapWith: <a href="#keyunwrapparams">KeyUnwrapParams</a>; rewrapWith: <a href="#keywrapparams">KeyWrapParams</a>; }</code> |

**Returns:** <code>Promise&lt;{ recoverableKey: <a href="#recoverablekey">RecoverableKey</a>; }&gt;</code>

--------------------


### recoverKey(...)

```typescript
recoverKey(options: { importAlias: string; recoverableKey: RecoverableKey; unwrapWith: KeyUnwrapParams; }) => Promise<void>
```

Unwraps and imports a previously-generated recoverable key into the key store. It may then be used to encrypt and decrypt values.

| Param         | Type                                                                                                                                                            |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`options`** | <code>{ importAlias: string; recoverableKey: <a href="#recoverablekey">RecoverableKey</a>; unwrapWith: <a href="#keyunwrapparams">KeyUnwrapParams</a>; }</code> |

--------------------


### recoverAgreementKeyPair(...)

```typescript
recoverAgreementKeyPair(options: { importAlias: string; recoverableKeyPair: RecoverableKeyPair; unwrapWith: KeyUnwrapParams; }) => Promise<void>
```

Unwraps and imports a previously-generated recoverable agreement key pair into the key store. It may then be used to encrypt and decrypt values.

| Param         | Type                                                                                                                                                                        |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`options`** | <code>{ importAlias: string; recoverableKeyPair: <a href="#recoverablekeypair">RecoverableKeyPair</a>; unwrapWith: <a href="#keyunwrapparams">KeyUnwrapParams</a>; }</code> |

--------------------


### recoverSignatureKeyPair(...)

```typescript
recoverSignatureKeyPair(options: { importAlias: string; recoverableKeyPair: RecoverableKeyPair; unwrapWith: KeyUnwrapParams; }) => Promise<void>
```

Unwraps and imports a previously-generated recoverable signature key pair into the key store. It may then be used to sign and verify values.

| Param         | Type                                                                                                                                                                        |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`options`** | <code>{ importAlias: string; recoverableKeyPair: <a href="#recoverablekeypair">RecoverableKeyPair</a>; unwrapWith: <a href="#keyunwrapparams">KeyUnwrapParams</a>; }</code> |

--------------------


### encrypt(...)

```typescript
encrypt(options: { encryptWith: KeyReference; cleartext: string; }) => Promise<{ encryptedMessage: EncryptedMessage; }>
```

Encrypts a string with a previously generated / recovered key or key pair. The encrypted string is returned in a structure of base64-encoded strings.

| Param         | Type                                                                                       |
| ------------- | ------------------------------------------------------------------------------------------ |
| **`options`** | <code>{ encryptWith: <a href="#keyreference">KeyReference</a>; cleartext: string; }</code> |

**Returns:** <code>Promise&lt;{ encryptedMessage: <a href="#encryptedmessage">EncryptedMessage</a>; }&gt;</code>

--------------------


### decrypt(...)

```typescript
decrypt(options: { decryptWith: KeyReference; encryptedMessage: EncryptedMessage; }) => Promise<{ cleartext: string; }>
```

Decrypts a string with a previously generated / recovered key or key pair.

| Param         | Type                                                                                                                                        |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| **`options`** | <code>{ decryptWith: <a href="#keyreference">KeyReference</a>; encryptedMessage: <a href="#encryptedmessage">EncryptedMessage</a>; }</code> |

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


### Type Aliases


#### RecoverableKeyPair

<code><a href="#passwordencryptedrecoverablekeypair">PasswordEncryptedRecoverableKeyPair</a> | <a href="#keyencryptedrecoverablekeypair">KeyEncryptedRecoverableKeyPair</a></code>


#### PasswordEncryptedRecoverableKeyPair

<code>{ privateKey: <a href="#passwordencryptedrecoverablekey">PasswordEncryptedRecoverableKey</a>, publicKey: string }</code>


#### PasswordEncryptedRecoverableKey

<code><a href="#encryptedmessage">EncryptedMessage</a> & { salt: string }</code>


#### EncryptedMessage

<code>{ ciphertext: string, iv: string }</code>


#### KeyEncryptedRecoverableKeyPair

<code>{ privateKey: <a href="#keyencryptedrecoverablekey">KeyEncryptedRecoverableKey</a>, publicKey: string }</code>


#### KeyEncryptedRecoverableKey

<code><a href="#encryptedmessage">EncryptedMessage</a></code>


#### KeyWrapParams

<code><a href="#passwordparamsmaybesalt">PasswordParamsMaybeSalt</a> | <a href="#keyreference">KeyReference</a></code>


#### PasswordParamsMaybeSalt

<code>{ password: string, salt?: string }</code>


#### KeyReference

<code><a href="#symmetrickeyreference">SymmetricKeyReference</a> | <a href="#derivedkeyreference">DerivedKeyReference</a></code>


#### SymmetricKeyReference

<code>{ keyAlias: string }</code>


#### DerivedKeyReference

<code><a href="#symmetrickeyreference">SymmetricKeyReference</a> & { publicKeyAlias: string, info?: string }</code>


#### RecoverableKey

<code><a href="#passwordencryptedrecoverablekey">PasswordEncryptedRecoverableKey</a> | <a href="#keyencryptedrecoverablekey">KeyEncryptedRecoverableKey</a></code>


#### KeyUnwrapParams

<code><a href="#passwordparams">PasswordParams</a> | <a href="#keyreference">KeyReference</a></code>


#### PasswordParams

<code>{ password: string }</code>

</docgen-api>
