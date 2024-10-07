import { 
    IDBFactory,
    IDBCursor,
    IDBCursorWithValue,
    IDBDatabase,
    IDBIndex,
    IDBKeyRange,
    IDBObjectStore,
    IDBOpenDBRequest,
    IDBRequest,
    IDBTransaction,
    IDBVersionChangeEvent,
} from 'fake-indexeddb';
import { writeFile } from 'fs/promises';
import webCrypto from 'tiny-webcrypto';
import { test as baseTest, vi, expect } from 'vitest';
import type { KeyManagerWebPlugin } from '../src/definitions';
import { base64Encode, KeyManager } from '../src/key-manager';
import { IdbKeyStore } from '../src/idb-key-store';

export function setupFakeIdb() {
    const fakeIndexedDB = new IDBFactory();

    globalThis.indexedDB = fakeIndexedDB;
    globalThis.IDBCursor = IDBCursor;
    globalThis.IDBCursorWithValue = IDBCursorWithValue;
    globalThis.IDBDatabase = IDBDatabase;
    globalThis.IDBFactory = IDBFactory;
    globalThis.IDBIndex = IDBIndex;
    globalThis.IDBKeyRange = IDBKeyRange;
    globalThis.IDBObjectStore = IDBObjectStore;
    globalThis.IDBOpenDBRequest = IDBOpenDBRequest;
    globalThis.IDBRequest = IDBRequest;
    globalThis.IDBTransaction = IDBTransaction;
    globalThis.IDBVersionChangeEvent = IDBVersionChangeEvent;
}

const test = baseTest.extend<{
    keyManager: KeyManagerWebPlugin
}>({
    keyManager: async ({}, use) => {
        setupFakeIdb();
        const keyManager = new KeyManager();
        await keyManager.useKeyStore(new IdbKeyStore);
        await use(keyManager);
    },
});
const publicKeyRegEx = /[a-zA-Z0-9\/\+\=]{212}/g;
const saltRegEx = /[a-zA-Z0-9\/\+\=]{172}/g;
const ivRegEx = /[a-zA-Z0-9\/\+\=]{16}/g;

const recoverableSigKeyPairJson = {
    "privateKey": {
        "ciphertext": "CrILhGlCg/XEN3LDk0/qsOatMJ/W3QMX5ATVTm7bcM9DAHFacMZRCEZq8yfS7WIucHaZ7mGJBZJcBASOy/p3Ue1FqQWgFPWUvffGIFTBsJHz6PA2b0A9a0jCMJ6kdqmkajqeO7FygxOHDf3Y3Uf9dZ5bW3yWlW9dO0rAreF54LxNPi6tZrpDGLxiWzW90tjEn/hhpw6CDHAw10LKXuMTykXQ5Ly9QBH4edYuVTedMX0y0FC/26KyQSQISbNSjdrGvVcMjjXT3e9FhSrk6vfCw28jlKZi5hDyouKnpHeMcUyqZCt29K/89qO+eQZYZ240oYzKnLosEuo8aJSmFvlcWyo=",
        "iv": "XqFZwuzIw8yc6MQl",
        "salt": "UfyXAyYhOPG2fVZac4pxb9DVphcaGa/5ynX2/LP3OsAJFn+UQAq+tZBfvEaXhnucQT+ZORXY71XYKQolrbkEaLDtQRMf6c6APe6ZGhQWCDmRsiFaYAGdwPH0jfCj4l/rx2ZRTPKNrUMaMegn4BqPMM25nlgDmtr5/k5Ds5bIgno="
    },
    "publicKey": "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBmRohtYjM4R120jr8cjTouYJ68qXssr+KUnxkcQ+eRei/ES+bZ2D3WLiVa2M0nItSFmCx0bitMlsKSczIPV2DkqoAKNditdQNIYgajNBmHcMhPykvMh+2qdshUIJekr6M1GSgXtiBmfT0ffHMgItBGbWJw4HiYIlZKXFRdJ3fVSyVOvs="
};

const recoverableAgreeKeyPairJson = {
    "privateKey": {
        "ciphertext": "1qgbz6J49/4FS2a+MS7Rbleb7+aK5hMTOKXX2a7EGRLI4Plef98AA82yqcQg2WsDiR277IntIC4GIUrJ3A5wNgqrOTVwsCJtfI/CX/y2d1/dFllQgzIG92leBls6E4XQKWDYf3roPiIE4YUY3Uokx5HpiP8z6N9beMlIOWM1M5KJTm8qyTflPHdyBepBmfiBf2sWALuXFR9YIbZ3WCbDrS/PgEKrBZFOKVca2lu/Pgi5tQqcgccBMStpv/Y6tPJtYT/72H+XqZMeUUfr05Ax7ddnKaPX9ocysacS9KtpffosWwgLnHJrYl03eXWt/hvm5mg5syJLSWK3xOhFePOI2SQ=",
        "iv": "driVYKcAg1wzQBT9",
        "salt": "D/qvJfEShcnyEgrPuoTvY2wRM8WJs9X6JOQHJleo+n1COZHd9pnOoL5dbrkCmvUo/FsCYGnDOWBOedN2o4GEHq+8+BieY2wGSTs/Dk+De/X35kcngeDhsM/eB9s1c4kX0qDzEpzxgRUOGQsalRKjBB+U2mT3yIGvIGNYAsjKsBY="
    },
    "publicKey": "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAJ0fRvGVuqr6gRytCjcwpSFfrPSd/gWDYq9gdr9lch1irR1wVN4s/b4DKkZ8lbnszoHy3XR3OajW+yx8XBgU2G/sB8T45Da45pHX4yVTyzTolN9lKNk6lLSQ5EI2vu4JVY5VZ/+BBHGagNjRn3W4cWW/I/RtbAj8F9kuhFhqxc1amQRw="
};

const recoverableKeyJson = {
    "ciphertext": "9XF2Ly8+uo1ng+x/XBIUZlIOwSoMYCahQf0CNMDQRQgaZVhFvr4VKpHWP+/bVEJw",
    "iv": "0kJLQny/GYm6itCZ",
    "salt": "x7/vx7ikOd122eMF7g0RbdwGKlZKyHDpJHJiJ58BBTH+w0Hys+o/zRw2KagXIr8oablCUAO0OqlLeTxjrn9ZwXKk9bNZ7O+1LUHHY0H8hYo/ouR3DUuxPh1dLlsvBLbww0V/7JKbt0zKwmnUhaxsQRfbWlzlqrcRm9+tbei7tms="
};

test('KeyManager#generateRecoverableSignatureKeyPair', async ({ keyManager }) => {
    const alias = 'Badonkey';
    const password = 'Scrammi';

    const { recoverableKeyPair } = await keyManager.generateRecoverableSignatureKeyPair({ password });
    // await writeFile('recoverable-sig-key-pair.json', JSON.stringify(recoverableKeyPair));

    expect(recoverableKeyPair).toEqual({
        publicKey: expect.stringMatching(publicKeyRegEx),
        privateKey: {
            salt: expect.stringMatching(saltRegEx),
            iv: expect.stringMatching(ivRegEx),
            ciphertext: expect.stringMatching(/[a-zA-Z0-9\/\+\=]{344}/g)
        }
    });

    await keyManager.recoverSignatureKeyPair({ alias, recoverableKeyPair, password });

    const { signature } = await keyManager.sign({
        keyAlias: alias,
        cleartext: 'Wigmans'
    });

    const { isValid } = await keyManager.verify({
        keyAlias: alias,
        cleartext: 'Wigmans',
        signature
    });

    expect(isValid).true;
});

test('KeyManager#recoverSignatureKeyPair', async ({ keyManager }) => {
    const alias = 'Badonkey';
    const password = 'Scrammi';

    await expect(() => keyManager.recoverSignatureKeyPair({
        alias,
        password: 'Bramson',
        recoverableKeyPair: recoverableSigKeyPairJson
    })).rejects.toThrowError();

    await keyManager.recoverSignatureKeyPair({
        alias,
        password,
        recoverableKeyPair: recoverableSigKeyPairJson
    });

    const { signature } = await keyManager.sign({
        keyAlias: alias,
        cleartext: 'Wigmans'
    });

    const { isValid } = await keyManager.verify({
        keyAlias: alias,
        cleartext: 'Wigmans',
        signature
    });

    expect(isValid).true;
});

test('KeyManager#importPublicSignatureKey', async ({ keyManager }) => {
    const keyPair = await webCrypto.subtle.generateKey(
        {
            name: "ECDSA",
            namedCurve: "P-521",
        },
        false,
        ["sign", "verify"],
    );

    await keyManager.importPublicSignatureKey({
        alias: 'OtherGuy',
        publicKey: base64Encode(await webCrypto.subtle.exportKey('spki', keyPair.publicKey))
    });

    const enc = new TextEncoder();
    
    const params : EcdsaParams = { name: 'ECDSA', hash: 'SHA-256' };

    const cleartext = "Donkey Bronkey";
    
    const signature = base64Encode(await webCrypto.subtle.sign(params, keyPair.privateKey, enc.encode(cleartext)));

    const { isValid } = await keyManager.verify({
        keyAlias: 'OtherGuy',
        cleartext,
        signature
    });

    expect(isValid).true;
    
    const { isValid: bogusIsValid } = await keyManager.verify({
        keyAlias: 'OtherGuy',
        cleartext: "BogusValue",
        signature
    });

    expect(bogusIsValid).false;
});

test('KeyManager#generateRecoverableAgreementKeyPair', async ({ keyManager }) => {
    const alias = 'Badonkey';
    const password = 'Scrammi';

    const { recoverableKeyPair } = await keyManager.generateRecoverableAgreementKeyPair({ password });

    // await writeFile('recoverable-agree-key-pair.json', JSON.stringify(recoverableKeyPair));

    expect(recoverableKeyPair).toEqual({
        publicKey: expect.stringMatching(publicKeyRegEx),
        privateKey: {
            salt: expect.stringMatching(saltRegEx),
            iv: expect.stringMatching(ivRegEx),
            ciphertext: expect.stringMatching(/[a-zA-Z0-9\/\+\=]{344}/g)
        }
    });

    await keyManager.recoverAgreementKeyPair({ alias, recoverableKeyPair, password });
    
    const cleartext = 'Wigmans';

    expect(
        (await keyManager
            .decryptWithAgreedKey({ 
                privateKeyAlias: 'Badonkey', 
                publicKeyAlias: 'Badonkey', 
                encryptedMessage: (await keyManager.encryptWithAgreedKey({
                    privateKeyAlias: 'Badonkey',
                    publicKeyAlias: 'Badonkey',
                    cleartext
                })).encryptedMessage
            })
        ).cleartext
    ).toBe(cleartext);

    await keyManager.importPublicAgreementKey({ alias: "OtherGuyKey", publicKey: recoverableAgreeKeyPairJson.publicKey });
    
    expect(
        (await keyManager
            .decryptWithAgreedKey({ 
                privateKeyAlias: 'Badonkey', 
                publicKeyAlias: 'OtherGuyKey', 
                encryptedMessage: (await keyManager.encryptWithAgreedKey({
                    privateKeyAlias: 'Badonkey',
                    publicKeyAlias: 'OtherGuyKey',
                    cleartext
                })).encryptedMessage
            })
        ).cleartext
    ).toBe(cleartext);

    expect(
        (await keyManager
            .decryptWithAgreedKey({ 
                privateKeyAlias: 'Badonkey', 
                publicKeyAlias: 'OtherGuyKey', 
                info: "Word",
                encryptedMessage: (await keyManager.encryptWithAgreedKey({
                    privateKeyAlias: 'Badonkey',
                    publicKeyAlias: 'OtherGuyKey',
                    info: "Word",
                    cleartext
                })).encryptedMessage
            })
        ).cleartext
    ).toBe(cleartext);
});

test('KeyManager#recoverAgreementKeyPair', async ({ keyManager }) => {
    await expect(() => keyManager.recoverAgreementKeyPair({
        alias: 'Badonkey',
        password: 'Bramson',
        recoverableKeyPair: recoverableAgreeKeyPairJson
    })).rejects.toThrowError();

    await keyManager.recoverAgreementKeyPair({
        alias: 'Badonkey',
        password: 'Scrammi',
        recoverableKeyPair: recoverableAgreeKeyPairJson
    });

    const cleartext = 'Wigmans';

    expect(
        (await keyManager
            .decryptWithAgreedKey({ 
                privateKeyAlias: 'Badonkey', 
                publicKeyAlias: 'Badonkey', 
                encryptedMessage: (await keyManager.encryptWithAgreedKey({
                    privateKeyAlias: 'Badonkey',
                    publicKeyAlias: 'Badonkey',
                    cleartext
                })).encryptedMessage
            })
        ).cleartext
    ).toBe(cleartext);
});

test('KeyManager#generateRecoverableKey', async ({ keyManager }) => {
    const alias = 'Badonkey';
    const password = 'Scrammi';

    const { recoverableKey } = await keyManager.generateRecoverableKey({ password: 'Scrammi' });

    // await writeFile('recoverable-key.json', JSON.stringify(recoverableKey));

    expect(recoverableKey).toEqual({
        salt: expect.stringMatching(saltRegEx),
        iv: expect.stringMatching(ivRegEx),
        ciphertext: expect.stringMatching(/[a-zA-Z0-9\/\+\=]{64}/g)
    });
    
    const cleartext = 'Wigmans';

    await keyManager.recoverKey({ alias, recoverableKey, password });

    expect(
        (await keyManager
            .decrypt({ 
                keyAlias: alias, 
                encryptedMessage: (await keyManager.encrypt({
                    keyAlias: alias,
                    cleartext
                })).encryptedMessage
            })
        ).cleartext
    ).toBe(cleartext);
});

test('KeyManager#recoverKey', async ({ keyManager }) => {
    const alias = 'Badonkey';
    const password = 'Scrammi';

    await expect(() => keyManager.recoverKey({
        alias,
        password: 'Bramson',
        recoverableKey: recoverableKeyJson
    })).rejects.toThrowError();

    await keyManager.recoverKey({
        alias,
        password,
        recoverableKey: recoverableKeyJson
    });

    const cleartext = 'Wigmans';

    expect(
        (await keyManager
            .decrypt({ 
                keyAlias: alias, 
                encryptedMessage: (await keyManager.encrypt({
                    keyAlias: alias,
                    cleartext
                })).encryptedMessage
            })
        ).cleartext
    ).toBe(cleartext);
});

test('KeyManager#reWrapKey', async ({ keyManager }) => {
    const alias = 'Badonkey';
    const password = 'Scrammi';

    await expect(() => keyManager.reWrapKey({
        currentPassword: 'WrongPassword',
        newPassword: 'Bimbo',
        recoverableKey: recoverableKeyJson
    })).rejects.toThrowError();

    const { recoverableKey } = await keyManager.reWrapKey({
        currentPassword: password,
        newPassword: 'Bimbo',
        recoverableKey: recoverableKeyJson
    });

    await expect(() => keyManager.recoverKey({
        alias,
        password,
        recoverableKey
    })).rejects.toThrowError();

    await keyManager.recoverKey({
        alias,
        password: 'Bimbo',
        recoverableKey
    });
});

test('KeyManager#reWrapSignatureKeyPair', async ({ keyManager }) => {
    const alias = 'Badonkey';
    const currentPassword = 'Scrammi';
    const newPassword = 'Bimbo';

    await expect(() => keyManager.reWrapSignatureKeyPair({
        currentPassword: 'WrongPassword',
        newPassword,
        recoverableKeyPair: recoverableSigKeyPairJson
    })).rejects.toThrowError();

    const { recoverableKeyPair } = await keyManager.reWrapSignatureKeyPair({
        currentPassword,
        newPassword,
        recoverableKeyPair: recoverableSigKeyPairJson
    });

    await expect(() => keyManager.recoverSignatureKeyPair({
        alias,
        password: currentPassword,
        recoverableKeyPair
    })).rejects.toThrowError();

    await keyManager.recoverSignatureKeyPair({
        alias,
        password: newPassword,
        recoverableKeyPair
    });
});

test('KeyManager#reWrapAgreementKeyPair', async ({ keyManager }) => {
    const alias = 'Badonkey';
    const currentPassword = 'Scrammi';
    const newPassword = 'Bimbo';

    await expect(() => keyManager.reWrapAgreementKeyPair({
        currentPassword: 'WrongPassword',
        newPassword,
        recoverableKeyPair: recoverableAgreeKeyPairJson
    })).rejects.toThrowError();

    const { recoverableKeyPair } = await keyManager.reWrapAgreementKeyPair({
        currentPassword,
        newPassword,
        recoverableKeyPair: recoverableAgreeKeyPairJson
    });

    await expect(() => keyManager.recoverAgreementKeyPair({
        alias,
        password: currentPassword,
        recoverableKeyPair
    })).rejects.toThrowError();

    await keyManager.recoverAgreementKeyPair({
        alias,
        password: newPassword,
        recoverableKeyPair
    });
});

test('KeyManager#checkAliasExists', async ({ keyManager }) => {
    await expect(keyManager.checkAliasExists({ keyAlias: 'Donker' })).resolves.toEqual({ aliasExists: false });
    await keyManager.generateKey({ keyAlias: 'Donker' });
    await expect(keyManager.checkAliasExists({ keyAlias: 'Donker' })).resolves.toEqual({ aliasExists: true });
    await expect(keyManager.checkAliasExists({ keyAlias: 'Stanko' })).resolves.toEqual({ aliasExists: false });
});

test('KeyManager#generateKey', async ({ keyManager }) => {
    await keyManager.generateKey({ keyAlias: 'Donker' });

    const cleartext = 'Banko';

    await expect(
        keyManager.decrypt({ 
            keyAlias: 'Donker', 
            encryptedMessage: (await keyManager.encrypt({ keyAlias: 'Donker', cleartext })).encryptedMessage 
        })
    ).resolves.toEqual({ cleartext })
});