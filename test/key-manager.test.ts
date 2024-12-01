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
import webCrypto from 'tiny-webcrypto';
import { test as baseTest, expect } from 'vitest';

import type { KeyManagerWebPlugin } from '../src/definitions';
import { IdbKeyStore } from '../src/idb-key-store';
import { base64Encode, KeyManager } from '../src/key-manager';

export function setupFakeIdb(): void {
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
    // eslint-disable-next-line no-empty-pattern
    keyManager: async ({}, use) => {
        setupFakeIdb();
        const keyManager = new KeyManager();
        await keyManager.useKeyStore(new IdbKeyStore);
        await use(keyManager);
    },
});
const publicKeyRegEx = /[a-zA-Z0-9/+=]{212}/g;
const saltRegEx = /[a-zA-Z0-9/+=]{172}/g;
const ivRegEx = /[a-zA-Z0-9/+=]{16}/g;
const encKeyRegex = /[a-zA-Z0-9/+=]{344}/g;
const encSymKeyRegex = /[a-zA-Z0-9/+=]{64}/g;

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
            decryptWith: { keyAlias: 'Donker' },
            encryptedMessage: (
                await keyManager.encrypt({ encryptWith: { keyAlias: 'Donker' }, cleartext })
            ).encryptedMessage 
        })
    ).resolves.toEqual({ cleartext });
});

test('KeyManager#generateRecoverableKey', async ({ keyManager }) => {
    const importAlias = 'Badonkey';
    const password = 'Scrammi';

    const { recoverableKey } = await keyManager.generateRecoverableKey({ password: 'Scrammi' });

    // await writeFile('recoverable-key.json', JSON.stringify(recoverableKey));

    expect(recoverableKey).toEqual({
        salt: expect.stringMatching(saltRegEx),
        iv: expect.stringMatching(ivRegEx),
        ciphertext: expect.stringMatching(encSymKeyRegex)
    });
    
    const cleartext = 'Wigmans';

    await keyManager.recoverKey({ importAlias, recoverableKey, unwrapWith: { password } });

    expect(
        (await keyManager
            .decrypt({
                decryptWith: { keyAlias: importAlias },
                encryptedMessage: (await keyManager.encrypt({
                    encryptWith: { keyAlias: importAlias },
                    cleartext
                })).encryptedMessage
            })
        ).cleartext
    ).toBe(cleartext);
});

test('KeyManager#generateRecoverableSignatureKeyPair', async ({ keyManager }) => {
    const importAlias = 'Badonkey';
    const password = 'Scrammi';

    const { recoverableKeyPair } = await keyManager.generateRecoverableSignatureKeyPair({ password });
    // await writeFile('recoverable-sig-key-pair.json', JSON.stringify(recoverableKeyPair));

    expect(recoverableKeyPair).toEqual({
        publicKey: expect.stringMatching(publicKeyRegEx),
        privateKey: {
            salt: expect.stringMatching(saltRegEx),
            iv: expect.stringMatching(ivRegEx),
            ciphertext: expect.stringMatching(encKeyRegex)
        }
    });

    await keyManager.recoverSignatureKeyPair({ importAlias, recoverableKeyPair, unwrapWith: { password } });

    const { signature } = await keyManager.sign({
        keyAlias: importAlias,
        cleartext: 'Wigmans'
    });

    const { isValid } = await keyManager.verify({
        keyAlias: importAlias,
        cleartext: 'Wigmans',
        signature
    });

    expect(isValid).true;
});

test('KeyManager#generateRecoverableAgreementKeyPair', async ({ keyManager }) => {
    const importAlias = 'Badonkey';
    const password = 'Scrammi';

    const { recoverableKeyPair } = await keyManager.generateRecoverableAgreementKeyPair({ password });

    // await writeFile('recoverable-agree-key-pair.json', JSON.stringify(recoverableKeyPair));

    expect(recoverableKeyPair).toEqual({
        publicKey: expect.stringMatching(publicKeyRegEx),
        privateKey: {
            salt: expect.stringMatching(saltRegEx),
            iv: expect.stringMatching(ivRegEx),
            ciphertext: expect.stringMatching(encKeyRegex)
        }
    });

    await keyManager.recoverAgreementKeyPair({ importAlias, recoverableKeyPair, unwrapWith: { password } });
    
    const cleartext = 'Wigmans';

    expect(
        (await keyManager
            .decrypt({ 
                decryptWith: { 
                    keyAlias: 'Badonkey',
                    publicKeyAlias: 'Badonkey'
                },
                encryptedMessage: (await keyManager.encrypt({
                    encryptWith: {
                        keyAlias: 'Badonkey',
                        publicKeyAlias: 'Badonkey',
                    },
                    cleartext
                })).encryptedMessage
            })
        ).cleartext
    ).toBe(cleartext);

    await keyManager.importPublicAgreementKey({ alias: "OtherGuyKey", publicKey: recoverableAgreeKeyPairJson.publicKey });
    
    expect(
        (await keyManager
            .decrypt({
                decryptWith: {
                    keyAlias: 'Badonkey', 
                    publicKeyAlias: 'OtherGuyKey', 
                },
                encryptedMessage: (await keyManager.encrypt({
                    encryptWith: {
                        keyAlias: 'Badonkey',
                        publicKeyAlias: 'OtherGuyKey',
                    },
                    cleartext
                })).encryptedMessage
            })
        ).cleartext
    ).toBe(cleartext);

    expect(
        (await keyManager
            .decrypt({ 
                decryptWith: {
                    keyAlias: 'Badonkey', 
                    publicKeyAlias: 'OtherGuyKey', 
                    info: "Word",
                },
                encryptedMessage: (await keyManager.encrypt({
                    encryptWith: {
                        keyAlias: 'Badonkey',
                        publicKeyAlias: 'OtherGuyKey',
                        info: "Word",
                    },
                    cleartext
                })).encryptedMessage
            })
        ).cleartext
    ).toBe(cleartext);
});

test('KeyManager#generateRecoverableAgreementKeyPair with key', async ({ keyManager }) => {
    const importAlias = 'Badonkey';
    const password = 'Scrammi';

    const { recoverableKey } = await keyManager.generateRecoverableKey({ password });
    await keyManager.recoverKey({ importAlias: 'WrappingKey', recoverableKey, unwrapWith: { password } });

    const { recoverableKeyPair } = await keyManager.generateRecoverableAgreementKeyPair({ keyAlias: 'WrappingKey' });

    expect(recoverableKeyPair).toEqual({
        publicKey: expect.stringMatching(publicKeyRegEx),
        privateKey: {
            iv: expect.stringMatching(ivRegEx),
            ciphertext: expect.stringMatching(encKeyRegex)
        }
    });

    await keyManager.recoverAgreementKeyPair({ importAlias, recoverableKeyPair, unwrapWith: { keyAlias: 'WrappingKey' } });
    
    const cleartext = 'Wigmans';

    expect(
        (await keyManager
            .decrypt({ 
                decryptWith: { 
                    keyAlias: 'Badonkey',
                    publicKeyAlias: 'Badonkey'
                },
                encryptedMessage: (await keyManager.encrypt({
                    encryptWith: {
                        keyAlias: 'Badonkey',
                        publicKeyAlias: 'Badonkey',
                    },
                    cleartext
                })).encryptedMessage
            })
        ).cleartext
    ).toBe(cleartext);

    await keyManager.importPublicAgreementKey({ alias: "OtherGuyKey", publicKey: recoverableAgreeKeyPairJson.publicKey });
    
    expect(
        (await keyManager
            .decrypt({
                decryptWith: {
                    keyAlias: 'Badonkey', 
                    publicKeyAlias: 'OtherGuyKey', 
                },
                encryptedMessage: (await keyManager.encrypt({
                    encryptWith: {
                        keyAlias: 'Badonkey',
                        publicKeyAlias: 'OtherGuyKey',
                    },
                    cleartext
                })).encryptedMessage
            })
        ).cleartext
    ).toBe(cleartext);

    expect(
        (await keyManager
            .decrypt({ 
                decryptWith: {
                    keyAlias: 'Badonkey', 
                    publicKeyAlias: 'OtherGuyKey', 
                    info: "Word",
                },
                encryptedMessage: (await keyManager.encrypt({
                    encryptWith: {
                        keyAlias: 'Badonkey',
                        publicKeyAlias: 'OtherGuyKey',
                        info: "Word",
                    },
                    cleartext
                })).encryptedMessage
            })
        ).cleartext
    ).toBe(cleartext);
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

test('KeyManager#importPublicAgreementKey', async ({ keyManager }) => {
    const importAlias = 'Badonkey';
    const password = 'Scrammi';

    const { recoverableKeyPair } = await keyManager.generateRecoverableAgreementKeyPair({ password });

    await keyManager.recoverAgreementKeyPair({ importAlias, recoverableKeyPair, unwrapWith: { password } });

    const otherKeyPair = await webCrypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-521",
        },
        false,
        ["deriveKey"],
    );

    await keyManager.importPublicAgreementKey({
        alias: 'OtherGuyKey',
        publicKey: base64Encode(await webCrypto.subtle.exportKey('spki', otherKeyPair.publicKey))
    });

    const cleartext = "Donkey Bronkey";

    expect(
        (await keyManager
            .decrypt({ 
                decryptWith: {
                    keyAlias: 'Badonkey', 
                    publicKeyAlias: 'OtherGuyKey', 
                    info: "Word",
                },
                encryptedMessage: (await keyManager.encrypt({
                    encryptWith: {
                        keyAlias: 'Badonkey',
                        publicKeyAlias: 'OtherGuyKey',
                        info: "Word",
                    },
                    cleartext
                })).encryptedMessage
            })
        ).cleartext
    ).toBe(cleartext);
});

test('KeyManager#recoverAgreementKeyPair', async ({ keyManager }) => {
    await expect(() => keyManager.recoverAgreementKeyPair({
        importAlias: 'Badonkey',
        unwrapWith: { password: 'Bramson' },
        recoverableKeyPair: recoverableAgreeKeyPairJson
    })).rejects.toThrowError();

    await keyManager.recoverAgreementKeyPair({
        importAlias: 'Badonkey',
        unwrapWith: { password: 'Scrammi' },
        recoverableKeyPair: recoverableAgreeKeyPairJson
    });

    const cleartext = 'Wigmans';

    expect(
        (await keyManager
            .decrypt({ 
                decryptWith: {
                    keyAlias: 'Badonkey', 
                    publicKeyAlias: 'Badonkey', 
                },
                encryptedMessage: (await keyManager.encrypt({
                    encryptWith: {
                        keyAlias: 'Badonkey',
                        publicKeyAlias: 'Badonkey',
                    },
                    cleartext
                })).encryptedMessage
            })
        ).cleartext
    ).toBe(cleartext);
});

test('KeyManager#recoverSignatureKeyPair', async ({ keyManager }) => {
    const importAlias = 'Badonkey';
    const password = 'Scrammi';

    await expect(() => keyManager.recoverSignatureKeyPair({
        importAlias,
        unwrapWith: { password: 'Bramson' },
        recoverableKeyPair: recoverableSigKeyPairJson
    })).rejects.toThrowError();

    await keyManager.recoverSignatureKeyPair({
        importAlias,
        unwrapWith: { password },
        recoverableKeyPair: recoverableSigKeyPairJson
    });

    const { signature } = await keyManager.sign({
        keyAlias: importAlias,
        cleartext: 'Wigmans'
    });

    const { isValid } = await keyManager.verify({
        keyAlias: importAlias,
        cleartext: 'Wigmans',
        signature
    });

    expect(isValid).true;
});

test('KeyManager#recoverKey', async ({ keyManager }) => {
    const importAlias = 'Badonkey';
    const password = 'Scrammi';

    await expect(() => keyManager.recoverKey({
        importAlias,
        unwrapWith: { 
            password: 'Bramson' 
        },
        recoverableKey: recoverableKeyJson
    })).rejects.toThrowError();

    await keyManager.recoverKey({
        importAlias,
        unwrapWith: { password },
        recoverableKey: recoverableKeyJson
    });

    const cleartext = 'Wigmans';

    expect(
        (await keyManager
            .decrypt({ 
                decryptWith: {
                    keyAlias: importAlias },
                encryptedMessage: (await keyManager.encrypt({
                    encryptWith: { keyAlias: importAlias },
                    cleartext
                })).encryptedMessage
            })
        ).cleartext
    ).toBe(cleartext);
});

test('KeyManager#rewrapKey', async ({ keyManager }) => {
    const importAlias = 'Badonkey';
    const password = 'Scrammi';

    await expect(() => keyManager.rewrapKey({
        unwrapWith: { password: 'WrongPassword' },
        rewrapWith: { password: 'Bimbo' },
        recoverableKey: recoverableKeyJson
    })).rejects.toThrowError();

    const { recoverableKey } = await keyManager.rewrapKey({
        unwrapWith: { password },
        rewrapWith: { password: 'Bimbo' },
        recoverableKey: recoverableKeyJson
    });

    await expect(() => keyManager.recoverKey({
        importAlias,
        unwrapWith: { password },
        recoverableKey
    })).rejects.toThrowError();

    await keyManager.recoverKey({
        importAlias,
        unwrapWith: { password: 'Bimbo' },
        recoverableKey
    });
});

test('KeyManager#rewrapKey with key', async ({ keyManager }) => {
    const importAlias = 'Badonkey';
    const password = 'Scrammi';

    const { recoverableKey: wrappingRecoverableKey } = await keyManager.generateRecoverableKey({ password });

    await keyManager.recoverKey({ importAlias: 'WrappingKey', recoverableKey: wrappingRecoverableKey, unwrapWith: { password } });
    
    await expect(() => keyManager.rewrapKey({
        unwrapWith: { password: 'WrongPassword' },
        rewrapWith: { password: 'Bimbo' },
        recoverableKey: recoverableKeyJson
    })).rejects.toThrowError();

    const { recoverableKey } = await keyManager.rewrapKey({
        unwrapWith: { password },
        rewrapWith: { keyAlias: 'WrappingKey' },
        recoverableKey: recoverableKeyJson
    });

    await expect(() => keyManager.recoverKey({
        importAlias,
        unwrapWith: { password },
        recoverableKey
    })).rejects.toThrowError();

    await keyManager.recoverKey({
        importAlias,
        unwrapWith: { keyAlias: 'WrappingKey' },
        recoverableKey
    });
});

test('KeyManager#rewrapKey with derived key and info', async ({ keyManager }) => {
    const importAlias = 'Badonkey';
    const password = 'Scrammi';

    const { recoverableKeyPair: wrappingRecoverableKeyPair } = await keyManager.generateRecoverableAgreementKeyPair({ password });

    await keyManager.recoverAgreementKeyPair({ importAlias: 'WrappingKey', recoverableKeyPair: wrappingRecoverableKeyPair, unwrapWith: { password } });
    
    await expect(() => keyManager.rewrapKey({
        unwrapWith: { password: 'WrongPassword' },
        rewrapWith: { password: 'Bimbo' },
        recoverableKey: recoverableKeyJson
    })).rejects.toThrowError();

    const { recoverableKey } = await keyManager.rewrapKey({
        unwrapWith: { password },
        rewrapWith: { keyAlias: 'WrappingKey', publicKeyAlias: 'WrappingKey', info: 'word' },
        recoverableKey: recoverableKeyJson
    });

    await expect(() => keyManager.recoverKey({
        importAlias,
        unwrapWith: { password },
        recoverableKey
    })).rejects.toThrowError();

    await keyManager.recoverKey({
        importAlias,
        unwrapWith: { keyAlias: 'WrappingKey', publicKeyAlias: 'WrappingKey', info: 'word' },
        recoverableKey
    });
});

test('KeyManager#rewrapKey with derived key', async ({ keyManager }) => {
    const importAlias = 'Badonkey';
    const password = 'Scrammi';

    const { recoverableKeyPair: wrappingRecoverableKeyPair } = await keyManager.generateRecoverableAgreementKeyPair({ password });

    await keyManager.recoverAgreementKeyPair({ importAlias: 'WrappingKey', recoverableKeyPair: wrappingRecoverableKeyPair, unwrapWith: { password } });
    
    await expect(() => keyManager.rewrapKey({
        unwrapWith: { password: 'WrongPassword' },
        rewrapWith: { password: 'Bimbo' },
        recoverableKey: recoverableKeyJson
    })).rejects.toThrowError();

    const { recoverableKey } = await keyManager.rewrapKey({
        unwrapWith: { password },
        rewrapWith: { keyAlias: 'WrappingKey', publicKeyAlias: 'WrappingKey' },
        recoverableKey: recoverableKeyJson
    });

    await expect(() => keyManager.recoverKey({
        importAlias,
        unwrapWith: { password },
        recoverableKey
    })).rejects.toThrowError();

    await keyManager.recoverKey({
        importAlias,
        unwrapWith: { keyAlias: 'WrappingKey', publicKeyAlias: 'WrappingKey' },
        recoverableKey
    });
});

test('KeyManager#reWrapSignatureKeyPair', async ({ keyManager }) => {
    const importAlias = 'Badonkey';
    const currentPassword = 'Scrammi';
    const newPassword = 'Bimbo';

    await expect(() => keyManager.rewrapSignatureKeyPair({
        unwrapWith: { password: 'WrongPassword' },
        rewrapWith: { password: newPassword },
        recoverableKeyPair: recoverableSigKeyPairJson
    })).rejects.toThrowError();

    const { recoverableKeyPair } = await keyManager.rewrapSignatureKeyPair({
        unwrapWith: { password: currentPassword },
        rewrapWith: { password: newPassword },
        recoverableKeyPair: recoverableSigKeyPairJson
    });

    await expect(() => keyManager.recoverSignatureKeyPair({
        importAlias,
        unwrapWith: { password: currentPassword },
        recoverableKeyPair
    })).rejects.toThrowError();

    await keyManager.recoverSignatureKeyPair({
        importAlias,
        unwrapWith: {
            password: newPassword 
        },
        recoverableKeyPair
    });
});

test('KeyManager#reWrapAgreementKeyPair', async ({ keyManager }) => {
    const importAlias = 'Badonkey';
    const currentPassword = 'Scrammi';
    const newPassword = 'Bimbo';

    await expect(() => keyManager.rewrapAgreementKeyPair({
        unwrapWith: { password: 'WrongPassword' },
        rewrapWith: { password: newPassword },
        recoverableKeyPair: recoverableAgreeKeyPairJson
    })).rejects.toThrowError();

    const { recoverableKeyPair } = await keyManager.rewrapAgreementKeyPair({
        unwrapWith: { password: currentPassword },
        rewrapWith: { password: newPassword },
        recoverableKeyPair: recoverableAgreeKeyPairJson
    });

    await expect(() => keyManager.recoverAgreementKeyPair({
        importAlias,
        unwrapWith: { password: currentPassword },
        recoverableKeyPair
    })).rejects.toThrowError();

    await keyManager.recoverAgreementKeyPair({
        importAlias,
        unwrapWith: {
            password: newPassword 
        },
        recoverableKeyPair
    });
});