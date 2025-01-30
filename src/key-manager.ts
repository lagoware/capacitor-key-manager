import webCrypto from 'tiny-webcrypto';

import type { IKeyStore, RecoverableKeyPair, RecoverableKey, KeyManagerPlugin, EncryptedMessage, KeyUnwrapParams, KeyWrapParams, KeyReference, DerivedKeyReference, SymmetricKeyReference, PasswordEncryptedRecoverableKey, KeyUnwrapParamsWithSalt, PasswordParamsMaybeSalt, PasswordEncryptedRecoverableKeyPair } from './definitions';

export function base64Decode(str: string): ArrayBuffer {
    return Uint8Array.from(atob(str), c => c.charCodeAt(0)).buffer;
}

export function base64Encode(buff: ArrayBuffer): string {
    return btoa(String.fromCharCode(...new Uint8Array(buff)))
}

function isSymmetricKeyReference(val: any): val is SymmetricKeyReference {
    return !!(val as SymmetricKeyReference)?.keyAlias;
}

function isDerivedKeyReference(val: any): val is DerivedKeyReference {
    return !!(val as DerivedKeyReference)?.publicKeyAlias;
}

function isPasswordParams(val: any): val is ({ password: string }) {
    return !!(val)?.password;
}

function isPasswordParamsWithSalt(val: any): val is ({ password: string, salt: string }) {
    return !!(val)?.password && !!(val)?.salt;
}

export class KeyManager implements KeyManagerPlugin {
    private keyStore : IKeyStore|null = null;

    useKeyStore(keyStore: IKeyStore): void {
        this.keyStore = keyStore;
    }

    async checkAliasExists({ keyAlias }: { keyAlias: string; }): Promise<{ aliasExists: boolean }> {
        if (!this.keyStore) {
            throw new Error(`KeyManager#checkAliasExists: no keyStore is loaded`);
        }
        return {
            aliasExists: (await Promise.all([
                this.keyStore.getCryptoKey(keyAlias),
                this.keyStore.getCryptoKeyPair(keyAlias),
            ]))
                .some(Boolean)
        };
    }

    async generateKey({ keyAlias }: { keyAlias: string }): Promise<void> {
        if (!this.keyStore) {
            throw new Error(`KeyManager#generateKey: no keyStore is loaded`);
        }
        const key = await webCrypto.subtle.generateKey(
            { 
                name: 'AES-GCM', 
                length: 256 
            },
            false,
            ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
        );
        await this.keyStore.putCryptoKey(keyAlias, key);
    }

    async generateRecoverableSignatureKeyPair(
        keyWrapParams : KeyWrapParams
    ): Promise<{ recoverableKeyPair: RecoverableKeyPair }> {
        const keyPair = await webCrypto.subtle.generateKey(
            {
                name: "ECDSA",
                namedCurve: "P-521",
            },
            true,
            ["sign", "verify"],
        );

        const recoverableKeyPair = await this.keyPairToRecoverableKeyPair(keyPair, keyWrapParams);

        return { recoverableKeyPair };
    }

    async generateRecoverableAgreementKeyPair(keyWrapParams : KeyWrapParams): Promise<{ recoverableKeyPair: RecoverableKeyPair }> {
        const keyPair = await webCrypto.subtle.generateKey(
            {
                name: "ECDH",
                namedCurve: "P-521",
            },
            true,
            ["deriveKey"],
        );

        const recoverableKeyPair = await this.keyPairToRecoverableKeyPair(keyPair, keyWrapParams);

        return { recoverableKeyPair };
    }
    
    async generateRecoverableKey(keyWrapParams : KeyWrapParams): Promise<{ recoverableKey: RecoverableKey }> {
        const key = await webCrypto.subtle.generateKey(
            { 
                name: 'AES-GCM', 
                length: 256 
            },
            true,
            ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
        );

        return { recoverableKey: await this.keyToRecoverableKey(key, keyWrapParams) };
    }

    async rewrapSignatureKeyPair({ 
        recoverableKeyPair,
        unwrapWith,
        rewrapWith
    }: {
        recoverableKeyPair: RecoverableKeyPair,
        unwrapWith: KeyUnwrapParams,
        rewrapWith: KeyWrapParams,
    }): Promise<{ recoverableKeyPair: RecoverableKeyPair; }> {
        const [ publicKey, privateKey ] = await Promise.all([
            this.deserializePublicSignatureKey(recoverableKeyPair.publicKey),
            this.unwrapSignaturePrivateKey(recoverableKeyPair.privateKey, unwrapWith, true)
        ]);

        return {
            recoverableKeyPair: await this.keyPairToRecoverableKeyPair({
                publicKey,
                privateKey,
            }, rewrapWith)
        }
    }
    
    async rewrapAgreementKeyPair(
        { recoverableKeyPair, unwrapWith, rewrapWith }: 
        {
            recoverableKeyPair: RecoverableKeyPair,
            unwrapWith: KeyUnwrapParams,
            rewrapWith: KeyWrapParams,
        }
    ): Promise<{ recoverableKeyPair: RecoverableKeyPair; }> {
        const [ publicKey, privateKey ] = await Promise.all([
            this.deserializePublicAgreementKey(recoverableKeyPair.publicKey),
            this.unwrapAgreementPrivateKey(recoverableKeyPair.privateKey, unwrapWith, true)
        ]);

        return {
            recoverableKeyPair: await this.keyPairToRecoverableKeyPair(
                {
                    publicKey,
                    privateKey,
                }, 
                rewrapWith
            )
        }
    }

    async rewrapKey(
        { recoverableKey, unwrapWith, rewrapWith }: 
        {
            recoverableKey: RecoverableKey,
            unwrapWith: KeyUnwrapParams,
            rewrapWith: KeyWrapParams,
        }
    ): Promise<{ recoverableKey: RecoverableKey; }> {
        const key = await this.unwrapKey(recoverableKey, unwrapWith, true);

        return {
            recoverableKey: await this.keyToRecoverableKey(key, rewrapWith)
        };
    }

    async recoverSignatureKeyPair(
        { importAlias, recoverableKeyPair, unwrapWith }:
        { importAlias: string, recoverableKeyPair: RecoverableKeyPair, unwrapWith: KeyUnwrapParams }
    ): Promise<void> {
        if (!this.keyStore) {
            throw new Error(`KeyManager#recoverSignatureKeyPair: no keyStore is loaded`);
        }

        const [ publicKey, privateKey ] = await Promise.all([
            this.deserializePublicSignatureKey(recoverableKeyPair.publicKey),
            this.unwrapSignaturePrivateKey(recoverableKeyPair.privateKey, unwrapWith, false)
        ]);

        const keyPair : CryptoKeyPair = {
            publicKey,
            privateKey
        };

        await this.keyStore.putCryptoKeyPair(importAlias, keyPair);
    }

    async recoverAgreementKeyPair(
        { importAlias, recoverableKeyPair, unwrapWith }:
        { importAlias: string, recoverableKeyPair: RecoverableKeyPair, unwrapWith: KeyUnwrapParams }
    ): Promise<void> {        
        if (!this.keyStore) {
            throw new Error(`KeyManager#recoverAgreementKeyPair: no keyStore is loaded`);
        }

        const [ publicKey, privateKey ] = await Promise.all([
            this.deserializePublicAgreementKey(recoverableKeyPair.publicKey),
            this.unwrapAgreementPrivateKey(recoverableKeyPair.privateKey, unwrapWith, false)
        ]);

        const keyPair : CryptoKeyPair = {
            publicKey,
            privateKey
        };

        await this.keyStore.putCryptoKeyPair(importAlias, keyPair);
    }

    async recoverKey(
        { importAlias, recoverableKey, unwrapWith }: 
        { importAlias: string, recoverableKey: RecoverableKey, unwrapWith: KeyUnwrapParams }
    ): Promise<void> {
        if (!this.keyStore) {
            throw new Error(`KeyManager#recoverKey: no keyStore is loaded`);
        }
        await this.keyStore.putCryptoKey(importAlias, await this.unwrapKey(recoverableKey, unwrapWith, false))
    }

    async importPublicSignatureKey({ alias, publicKey }: { alias: string, publicKey: string }): Promise<void> {    
        if (!this.keyStore) {
            throw new Error(`KeyManager#importPublicSignatureKey: no keyStore is loaded`);
        }

        await this.keyStore.putCryptoKey(alias, await this.deserializePublicSignatureKey(publicKey));
    }
    
    async importPublicAgreementKey({ alias, publicKey }: { alias: string, publicKey: string }): Promise<void> {    
        if (!this.keyStore) {
            throw new Error(`KeyManager#importPublicAgreementKey: no keyStore is loaded`);
        }

        await this.keyStore.putCryptoKey(alias, await this.deserializePublicAgreementKey(publicKey));
    }

    async encrypt({ encryptWith, cleartext }: { encryptWith: KeyReference; cleartext: string; }): Promise<{ encryptedMessage: EncryptedMessage; }> {
        const key = await this.resolveEncryptionKey(encryptWith);

        if (!key) {
            throw new Error('No encryption key could be resolved');
        }
        
        return {
            encryptedMessage: await this.encryptWithKey(cleartext, key)
        }
    }

    async decrypt({ decryptWith, encryptedMessage }: { decryptWith: KeyReference, encryptedMessage: EncryptedMessage }): Promise<{ cleartext: string; }> {
        const key = await this.resolveEncryptionKey(decryptWith);

        if (!key) {
            throw new Error('No decryption key could be resolved');
        }

        return {
            cleartext: await this.decryptWithKey(encryptedMessage, key)
        };
    }

    async sign({ keyAlias, cleartext }: { keyAlias: string, cleartext: string }): Promise<{ signature: string}> {
        const keyPair = await this.resolveKeyPair(keyAlias);

        const enc = new TextEncoder();
        
        const params : EcdsaParams = { name: 'ECDSA', hash: 'SHA-256' };
        
        const sig = await webCrypto.subtle.sign(params, keyPair.privateKey, enc.encode(cleartext));

        return { signature: base64Encode(sig) };
    }

    async verify({ keyAlias, cleartext, signature }: { signature: string, keyAlias: string, cleartext: string }): Promise<{ isValid: boolean }> {
        let publicKey : CryptoKey;
        
        try {
            publicKey = await this.resolveKey(keyAlias);
            if (publicKey.type !== 'public') {
                throw new Error(`KeyManager#verify: resolved key ${keyAlias} is not a public key`);
            }
        } catch (err) {
            publicKey = (await this.resolveKeyPair(keyAlias))?.publicKey;
        }

        if (!publicKey) {
            throw new Error(`KeyManager#verify: could not resolve key ${keyAlias}`);
        }

        const params : EcdsaParams = { name: 'ECDSA', hash: 'SHA-256' };

        const enc = new TextEncoder();

        const isValid = await webCrypto.subtle.verify(params, publicKey, base64Decode(signature), enc.encode(cleartext) )

        return { isValid };
    }

    private async resolveDerivedKey({ keyAlias, publicKeyAlias, info }: DerivedKeyReference) {
        const { privateKey, publicKey } = await this.resolveAgreementKeys(keyAlias, publicKeyAlias);
        
        return this.deriveEncryptionKey(privateKey, publicKey, info);
    }

    private async resolveEncryptionKey(keyReference: KeyReference): Promise<CryptoKey|null> {
        if (isDerivedKeyReference(keyReference)) {
            return this.resolveDerivedKey(keyReference);
        } else if (isSymmetricKeyReference(keyReference)) {
            return this.resolveKey(keyReference.keyAlias);
        }
        return null;
    }

    private async resolveWrappingKey(unwrapParams: KeyUnwrapParamsWithSalt): Promise<CryptoKey> {
        const encKey = await this.resolveEncryptionKey(unwrapParams as KeyReference);
        if (encKey) {
            return encKey;
        } else if (isPasswordParamsWithSalt(unwrapParams)) {
            return await this.deriveKeyFromPassword(unwrapParams.password, base64Decode(unwrapParams.salt));
        }
        throw new Error('Unrecognized unwrapParams format');
    }

    private addSaltToUnwrapParams(unwrapParams: KeyUnwrapParams, recoverableKey: RecoverableKey): KeyUnwrapParamsWithSalt {
        if (isPasswordParams(unwrapParams)) {
            return { ...unwrapParams, salt: (recoverableKey as PasswordEncryptedRecoverableKey).salt }
        }
        return unwrapParams;
    }

    private fillGeneratedSaltToUnwrapParams(unwrapParams: KeyUnwrapParams): KeyUnwrapParamsWithSalt {
        if (isPasswordParams(unwrapParams)) {
            const { salt } = (unwrapParams as PasswordParamsMaybeSalt);
            return { 
                ...unwrapParams, 
                salt: salt ?? base64Encode(webCrypto.getRandomValues(new Uint8Array(128)))
            }
        }
        return unwrapParams;
    }

    private async unwrapSignaturePrivateKey(recoverableKey: RecoverableKey, unwrapParams: KeyUnwrapParams, extractable: boolean): Promise<CryptoKey> {
        const wrappingKey = await this.resolveWrappingKey(
            this.addSaltToUnwrapParams(unwrapParams, recoverableKey)
        );

        return webCrypto.subtle.unwrapKey(
            'pkcs8',
            base64Decode(recoverableKey.ciphertext),
            wrappingKey,
            {
                name: 'AES-GCM',
                iv: base64Decode(recoverableKey.iv)
            },
            {
                name: "ECDSA",
                namedCurve: "P-521",
            },
            extractable,
            ['sign']
        );
    }

    private async unwrapAgreementPrivateKey(recoverableKey: RecoverableKey, unwrapParams: KeyUnwrapParams, extractable: boolean): Promise<CryptoKey> {
        const wrappingKey = await this.resolveWrappingKey(
            this.addSaltToUnwrapParams(unwrapParams, recoverableKey)
        );

        return webCrypto.subtle.unwrapKey(
            'pkcs8',
            base64Decode(recoverableKey.ciphertext),
            wrappingKey,
            {
                name: 'AES-GCM',
                iv: base64Decode(recoverableKey.iv)
            },
            {
                name: "ECDH",
                namedCurve: "P-521",
            },
            extractable,
            ['deriveKey']
        );
    }
    
    private async unwrapKey(recoverableKey: RecoverableKey, unwrapParams: KeyUnwrapParams, extractable: boolean ) {
        const wrappingKey = await this.resolveWrappingKey(
            this.addSaltToUnwrapParams(unwrapParams, recoverableKey)
        );
        
        return webCrypto.subtle.unwrapKey(
            'raw',
            base64Decode(recoverableKey.ciphertext),
            wrappingKey,
            { name: 'AES-GCM', iv: base64Decode(recoverableKey.iv) },
            { name: 'AES-GCM', length: 256 },
            extractable,
            ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
        );
    }

    private async wrapKeyWithKey(keyToWrap: CryptoKey, wrappingKey: CryptoKey): Promise<EncryptedMessage> {
        const iv = webCrypto.getRandomValues(new Uint8Array(12));

        const key = await webCrypto.subtle.wrapKey(
            keyToWrap.algorithm.name == 'AES-GCM' 
                ? 'raw' 
                : 'pkcs8',
            keyToWrap,
            wrappingKey,
            {
                name: 'AES-GCM',
                iv
            }
        );

        return { ciphertext: base64Encode(key), iv: base64Encode(iv.buffer) };
    }
    
    private async deserializePublicSignatureKey(publicKey: string ) {
        return webCrypto.subtle.importKey('spki', base64Decode(publicKey), {
            name: "ECDSA",
            namedCurve: "P-521",
        }, true, ['verify'])
    }

    private async deserializePublicAgreementKey(publicKey: string ) {
        return webCrypto.subtle.importKey('spki', base64Decode(publicKey), {
            name: "ECDH",
            namedCurve: "P-521",
        }, true, []);
    }

    private async decryptWithKey(encryptedMessage: EncryptedMessage, encryptionKey: CryptoKey): Promise<string> {
        const decryptedBuff = await webCrypto.subtle.decrypt(
            { 
                name: 'AES-GCM', 
                iv: base64Decode(encryptedMessage.iv) 
            },
            encryptionKey,
            base64Decode(encryptedMessage.ciphertext),
        );
        
        const dec = new TextDecoder();

        return dec.decode(decryptedBuff);
    }

    private async encryptWithKey(cleartext: string, encryptionKey: CryptoKey): Promise<EncryptedMessage> {
        const iv = webCrypto.getRandomValues(new Uint8Array(12));
        const enc = new TextEncoder();

        const encryptedBuffer = await webCrypto.subtle.encrypt({
            name: "AES-GCM",
            iv,
        }, encryptionKey, enc.encode(cleartext));

        return {
            iv: base64Encode(iv),
            ciphertext: base64Encode(encryptedBuffer)
        }
    }
  
    private async resolveKey(keyAlias: string): Promise<CryptoKey> {
        if (!this.keyStore) {
            throw new Error(`KeyManager#resolveKey: no keyStore is loaded`);
        }
        
        const key: CryptoKey|null = await this.keyStore.getCryptoKey(keyAlias);

        if (!key) {
            throw new Error(`No key with alias ${keyAlias} was found`);
        }
        return key;
    }

    private async resolveAgreementKeys(privateKeyAlias: string, publicKeyAlias: string): Promise<CryptoKeyPair> {
        if (!this.keyStore) {
            throw new Error(`KeyManager#resolveAgreementKeys: no keyStore is loaded`);
        }
        const keyPair = await this.keyStore.getCryptoKeyPair(privateKeyAlias);
        
        if (!keyPair) {
            throw new Error(`KeyManager#resolveAgreementKeys: key pair with alias ${privateKeyAlias} does not exist`);
        }

        const publicKey: CryptoKey|null = privateKeyAlias === publicKeyAlias
            ? keyPair.publicKey
            : (await this.keyStore.getCryptoKey(publicKeyAlias));

        if (!publicKey) {
            throw new Error(`KeyManager#resolveAgreementKeys: public key with alias ${publicKeyAlias} does not exist`);
        }

        return {
            publicKey,
            privateKey: keyPair.privateKey
        }
    }

    private async resolveKeyPair(keyAlias: string): Promise<CryptoKeyPair> {
        if (!this.keyStore) {
            throw new Error(`KeyManager#resolveKeyPair: no keyStore is loaded`);
        }
        const keyPair = await this.keyStore.getCryptoKeyPair(keyAlias);
        
        if (!keyPair) {
            throw new Error(`KeyManager#resolveKeyPair: key pair with alias ${keyAlias} does not exist`);
        }
        return keyPair;
    }

    private async keyPairToRecoverableKeyPair(keyPair: CryptoKeyPair, wrapParams: KeyWrapParams): Promise<RecoverableKeyPair> {
        const params = this.fillGeneratedSaltToUnwrapParams(wrapParams);
        const wrappingKey = await this.resolveWrappingKey(params);

        const privateKey = await this.wrapKeyWithKey(keyPair.privateKey, wrappingKey);

        const publicKey = base64Encode(await webCrypto.subtle.exportKey('spki', keyPair.publicKey));

        if (isPasswordParamsWithSalt(params)) {
            const recoverableKeyPair : PasswordEncryptedRecoverableKeyPair = { 
                privateKey: { 
                    ...privateKey, 
                    salt: params.salt
                },
                publicKey 
            };

            return recoverableKeyPair;
        }

        return {
            privateKey,
            publicKey
        };
    }    

    private async keyToRecoverableKey(key: CryptoKey, wrapParams: KeyWrapParams): Promise<RecoverableKey> {
        const params = this.fillGeneratedSaltToUnwrapParams(wrapParams);
        const wrappingKey = await this.resolveWrappingKey(params);

        const encryptedPrivateKey = await this.wrapKeyWithKey(key, wrappingKey);

        if (isPasswordParamsWithSalt(params)) {
            const recoverableKeyPair : PasswordEncryptedRecoverableKey = { 
                ...encryptedPrivateKey, 
                salt: params.salt
            };

            return recoverableKeyPair;
        }
        return encryptedPrivateKey;
    }

    private async deriveKeyFromPassword(password: string, salt: ArrayBuffer) {
        const enc = new TextEncoder();
        
        const passwordKey = await webCrypto.subtle.importKey(
            "raw",
            enc.encode(password),
            { name: "PBKDF2" },
            false,
            ["deriveBits", "deriveKey"],
        );

        const derivedKey = await webCrypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt,
                iterations: 100000,
                hash: "SHA-256",
            },
            passwordKey,
            { name: "AES-GCM", length: 256 },
            false,
            ['wrapKey', 'unwrapKey', 'encrypt', 'decrypt']
        );

        return derivedKey;
    }

    private async deriveEncryptionKey(privateKey: CryptoKey, publicKey: CryptoKey, info?: string) {
        const agreedKey = await webCrypto.subtle.deriveKey(
            {
              name: "ECDH",
              public: publicKey,
            },
            privateKey,
            info != null 
                ? {
                    name: 'HKDF',
                    length: 256
                } 
                : {
                    name: "AES-GCM",
                    length: 256,
                },
            false,
            info != null ? ["deriveKey"] : ['wrapKey', 'unwrapKey', 'encrypt', 'decrypt'],
        );
        
        let encryptionKey = agreedKey;

        if (info != null) {
            const enc = new TextEncoder();

            encryptionKey = await webCrypto.subtle.deriveKey(
                {
                    name: "HKDF",
                    salt: new Uint8Array(),
                    info: enc.encode(info),
                    hash: "SHA-256",
                },
                agreedKey,
                { name: "AES-GCM", length: 256 },
                false,
                ['wrapKey', 'unwrapKey', 'encrypt', 'decrypt'],
            );
        }

        return encryptionKey;
    }

}