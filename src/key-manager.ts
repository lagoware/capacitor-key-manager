import type { IKeyStore, RecoverableKeyPair, RecoverableKey, KeyManagerWebPlugin, EncryptedMessage } from './definitions';
import webCrypto from 'tiny-webcrypto';

export function base64Decode(str: string): ArrayBuffer {
    return Uint8Array.from(atob(str), c => c.charCodeAt(0)).buffer;
}

export function base64Encode(buff: ArrayBuffer): string {
    return btoa(String.fromCharCode(...new Uint8Array(buff)))
}

export class KeyManager implements KeyManagerWebPlugin {
    private keyStore : IKeyStore|null = null;

    async useKeyStore(keyStore: IKeyStore) {
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

    async generateKey({ keyAlias }: { keyAlias: string }) {
        if (!this.keyStore) {
            throw new Error(`KeyManager#generateKey: no keyStore is loaded`);
        }
        const key = await webCrypto.subtle.generateKey(
            { 
                name: 'AES-GCM', 
                length: 256 
            },
            false,
            ['encrypt', 'decrypt']
        );
        await this.keyStore.putCryptoKey(keyAlias, key);
    }

    async generateRecoverableSignatureKeyPair({ password, salt } : { password: string, salt?: string }) {
        const keyPair = await webCrypto.subtle.generateKey(
            {
                name: "ECDSA",
                namedCurve: "P-521",
            },
            true,
            ["sign", "verify"],
        );

        const recoverableKeyPair = await this.keyPairToRecoverableKeyPair(keyPair, password, salt);

        return { recoverableKeyPair };
    }

    async generateRecoverableAgreementKeyPair({ password, salt } : { password: string, salt?: string  }) {
        const keyPair = await webCrypto.subtle.generateKey(
            {
                name: "ECDH",
                namedCurve: "P-521",
            },
            true,
            ["deriveKey"],
        );

        const recoverableKeyPair = await this.keyPairToRecoverableKeyPair(keyPair, password, salt);

        return { recoverableKeyPair };
    }
    
    async generateRecoverableKey({ password, salt }: { password: string; salt?: string; }): Promise<{ recoverableKey: RecoverableKey }> {
        const key = await webCrypto.subtle.generateKey(
            { 
                name: 'AES-GCM', 
                length: 256 
            },
            true,
            ['encrypt', 'decrypt']
        );

        return { recoverableKey: await this.keyToRecoverableKey(key, password, salt) };
    }

    async reWrapSignatureKeyPair({ recoverableKeyPair, currentPassword, newPassword, newSalt }: { currentPassword: string; newPassword: string; newSalt?: string; recoverableKeyPair: RecoverableKeyPair; }): Promise<{ recoverableKeyPair: RecoverableKeyPair; }> {
        return {
            recoverableKeyPair: await this.keyPairToRecoverableKeyPair({
                publicKey: await this.deserializePublicSignatureKey(recoverableKeyPair.publicKey),
                privateKey: await this.unwrapSignaturePrivateKey(recoverableKeyPair.privateKey, currentPassword, true),
            }, newPassword, newSalt)
        }
    }
    
    async reWrapAgreementKeyPair({ recoverableKeyPair, currentPassword, newPassword, newSalt }: { currentPassword: string; newPassword: string; newSalt?: string; recoverableKeyPair: RecoverableKeyPair; }): Promise<{ recoverableKeyPair: RecoverableKeyPair; }> {
        return {
            recoverableKeyPair: await this.keyPairToRecoverableKeyPair({
                publicKey: await this.deserializePublicAgreementKey(recoverableKeyPair.publicKey),
                privateKey: await this.unwrapAgreementPrivateKey(recoverableKeyPair.privateKey, currentPassword, true),
            }, newPassword, newSalt)
        }
    }

    async reWrapKey({ recoverableKey, currentPassword, newPassword, newSalt }: { currentPassword: string; newPassword: string; newSalt?: string; recoverableKey: RecoverableKey; }): Promise<{ recoverableKey: RecoverableKey; }> {
        const key = await this.unwrapKey(recoverableKey, currentPassword, true);

        return {
            recoverableKey: await this.keyToRecoverableKey(key, newPassword, newSalt)
        };
    }

    async recoverSignatureKeyPair({ alias, recoverableKeyPair, password }: { alias: string; recoverableKeyPair: RecoverableKeyPair; password: string; }): Promise<void> {
        if (!this.keyStore) {
            throw new Error(`KeyManager#recoverSignatureKeyPair: no keyStore is loaded`);
        }

        const keyPair : CryptoKeyPair = {
            publicKey: await this.deserializePublicSignatureKey(recoverableKeyPair.publicKey),
            privateKey: await this.unwrapSignaturePrivateKey(recoverableKeyPair.privateKey, password, false)
        };

        await this.keyStore.putCryptoKeyPair(alias, keyPair);
    }

    async recoverAgreementKeyPair({ alias, recoverableKeyPair, password }: { alias: string; recoverableKeyPair: RecoverableKeyPair; password: string; }): Promise<void> {        
        if (!this.keyStore) {
            throw new Error(`KeyManager#recoverAgreementKeyPair: no keyStore is loaded`);
        }

        const keyPair : CryptoKeyPair = {
            publicKey: await this.deserializePublicAgreementKey(recoverableKeyPair.publicKey),
            privateKey: await this.unwrapAgreementPrivateKey(recoverableKeyPair.privateKey, password, false)
        };

        await this.keyStore.putCryptoKeyPair(alias, keyPair);
    }

    async recoverKey({ alias, recoverableKey, password }: { alias: string; recoverableKey: RecoverableKey; password: string; }): Promise<void> {
        if (!this.keyStore) {
            throw new Error(`KeyManager#recoverKey: no keyStore is loaded`);
        }
        
        await this.keyStore.putCryptoKey(alias, await this.unwrapKey(recoverableKey, password, false))
    }

    async importPublicSignatureKey({ alias, publicKey }: { alias: string, publicKey: string }) {    
        if (!this.keyStore) {
            throw new Error(`KeyManager#importPublicSignatureKey: no keyStore is loaded`);
        }

        await this.keyStore.putCryptoKey(alias, await this.deserializePublicSignatureKey(publicKey));
    }
    
    async importPublicAgreementKey({ alias, publicKey }: { alias: string, publicKey: string }) {    
        if (!this.keyStore) {
            throw new Error(`KeyManager#importPublicAgreementKey: no keyStore is loaded`);
        }

        await this.keyStore.putCryptoKey(alias, await this.deserializePublicAgreementKey(publicKey));
    }

    async encrypt({ keyAlias, cleartext }: { keyAlias: string; cleartext: string; }): Promise<{ encryptedMessage: EncryptedMessage; }> {
        const key = await this.resolveKey(keyAlias);
        
        return {
            encryptedMessage: await this.encryptWithKey(cleartext, key)
        }
    }

    async decrypt({ keyAlias, encryptedMessage }: { keyAlias: string; encryptedMessage: EncryptedMessage; }): Promise<{ cleartext: string; }> {
        const key = await this.resolveKey(keyAlias);

        return {
            cleartext: await this.decryptWithKey(encryptedMessage, key)
        };
    }

    async decryptWithAgreedKey({ privateKeyAlias, publicKeyAlias, encryptedMessage, info }: { privateKeyAlias: string; publicKeyAlias: string; encryptedMessage: EncryptedMessage; info?: string; }): Promise<{ cleartext: string  }> {
        const { privateKey, publicKey } = await this.resolveAgreementKeys(privateKeyAlias, publicKeyAlias);
        
        const encryptionKey = await this.deriveEncryptionKey(privateKey, publicKey, info);

        return {
            cleartext: await this.decryptWithKey(encryptedMessage, encryptionKey)
        }
    }

    async encryptWithAgreedKey({ privateKeyAlias, publicKeyAlias, cleartext, info }: { privateKeyAlias: string; publicKeyAlias: string; cleartext: string; info?: string; }): Promise<{ encryptedMessage: EncryptedMessage; }> {
        const { privateKey, publicKey } = await this.resolveAgreementKeys(privateKeyAlias, publicKeyAlias);

        const encryptionKey = await this.deriveEncryptionKey(privateKey, publicKey, info);

        return {
            encryptedMessage: await this.encryptWithKey(cleartext, encryptionKey)
        }
    }

    async sign({ keyAlias, cleartext }: { keyAlias: string, cleartext: string }) {
        const keyPair = await this.resolveKeyPair(keyAlias);

        const enc = new TextEncoder();
        
        const params : EcdsaParams = { name: 'ECDSA', hash: 'SHA-256' };
        
        const sig = await webCrypto.subtle.sign(params, keyPair.privateKey, enc.encode(cleartext));

        return { signature: base64Encode(sig) };
    }

    async verify({ keyAlias, cleartext, signature }: { signature: string, keyAlias: string, cleartext: string }) {
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

    private async unwrapSignaturePrivateKey(recoverableKey: RecoverableKey, password: string, extractable: boolean): Promise<CryptoKey> {
        return webCrypto.subtle.unwrapKey(
            'pkcs8',
            base64Decode(recoverableKey.ciphertext),
            (await this.deriveKeyFromPassword(password, recoverableKey.salt)).key,
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

    private async unwrapAgreementPrivateKey(recoverableKey: RecoverableKey, password: string, extractable: boolean): Promise<CryptoKey> {
        return webCrypto.subtle.unwrapKey(
            'pkcs8',
            base64Decode(recoverableKey.ciphertext),
            (await this.deriveKeyFromPassword(password, recoverableKey.salt)).key,
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
    
    private async unwrapKey(recoverableKey: RecoverableKey, password: string, extractable: boolean ) {
        return webCrypto.subtle.unwrapKey(
            'raw',
            base64Decode(recoverableKey.ciphertext),
            (await this.deriveKeyFromPassword(password, recoverableKey.salt)).key,
            { name: 'AES-GCM', iv: base64Decode(recoverableKey.iv) },
            { name: 'AES-GCM', length: 256 },
            extractable,
            ['encrypt','decrypt']
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
        
        let key: CryptoKey|null = await this.keyStore.getCryptoKey(keyAlias);

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

        let publicKey: CryptoKey|null = privateKeyAlias === publicKeyAlias
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

    private async keyPairToRecoverableKeyPair(keyPair: CryptoKeyPair, password: string, salt?: string): Promise<RecoverableKeyPair> {
        const keyEncryptionKey = await this.deriveKeyFromPassword(password, salt);
        const encryptedPrivateKey = await this.wrapKeyWithKey(keyPair.privateKey, keyEncryptionKey.key);
        const publicKey = base64Encode(await webCrypto.subtle.exportKey('spki', keyPair.publicKey));

        const recoverableKeyPair: RecoverableKeyPair = { 
            privateKey: { 
                ...encryptedPrivateKey, 
                salt: base64Encode(keyEncryptionKey.salt) 
            },  
            publicKey 
        };

        return recoverableKeyPair;
    }    

    private async keyToRecoverableKey(key: CryptoKey, password: string, salt?: string): Promise<RecoverableKey> {
        const keyEncryptionKey = await this.deriveKeyFromPassword(password, salt);
        const encryptedPrivateKey = await this.wrapKeyWithKey(key, keyEncryptionKey.key);

        return {            
            ...encryptedPrivateKey, 
            salt: base64Encode(keyEncryptionKey.salt) 
        };
    }

    private async deriveKeyFromPassword(password: string, saltStr?: string) {
        const salt = saltStr
            ? base64Decode(saltStr)
            : webCrypto.getRandomValues(new Uint8Array(128));

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

        return { key: derivedKey, salt };
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
            info != null ? ["deriveKey"] : ["encrypt", "decrypt"],
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
                ["encrypt", "decrypt"],
            );
        }

        return encryptionKey;
    }

}