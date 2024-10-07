
import type { DBSchema, IDBPDatabase } from 'idb';
import type { IKeyStore } from './definitions';

import { openDB } from 'idb';

export interface KeyStoreDbSchema extends DBSchema {
    keyPairs: {
      key: string,
      value: CryptoKeyPair
    },
    keys: {
      key: string,
      value: CryptoKey
    }
}

export const runKeyStoreDbUpgrade = async (
    db: IDBPDatabase<KeyStoreDbSchema>, 
    oldVersion: number, 
    newVersion: number|null
): Promise<void> => {
    switch (oldVersion) {
        case 0:
            if (newVersion != null && newVersion >= 1) {
                db.createObjectStore('keyPairs');
                db.createObjectStore('keys');
            }
            break;
        default:
            throw new Error(`Invalid db version ${oldVersion}`);
    }
};

const defaultDbLoader = async () => {
    return openDB<KeyStoreDbSchema>('CapacitorKeyManager', 1, {
        async upgrade(db, oldVersion, newVersion) {
            await runKeyStoreDbUpgrade(db, oldVersion, newVersion)
        }
    });
};

export class IdbKeyStore implements IKeyStore {
    private _db : Promise<IDBPDatabase<KeyStoreDbSchema>>|null;
    private dbLoader : () => Promise<IDBPDatabase<KeyStoreDbSchema>>;

    constructor({ dbLoader=defaultDbLoader } : { dbLoader?: () => Promise<IDBPDatabase<KeyStoreDbSchema>>  }={}) {
        this.dbLoader = dbLoader;
        this._db = null;
    }

    get db(): Promise<IDBPDatabase<KeyStoreDbSchema>> {
        return this._db ?? (this._db = this.dbLoader());
    }

    async getCryptoKey(alias: string) {
        const db = await this.db;

        return (await db.get('keys', alias)) ?? null;
    }

    async getCryptoKeyPair(alias: string) {
        const db = await this.db;

        return (await db.get('keyPairs', alias)) ?? null;
    }

    async putCryptoKeyPair(alias: string, keyPair: CryptoKeyPair) {
        const db = await this.db;

        await db.put('keyPairs', keyPair, alias);
    }

    async putCryptoKey(alias: string, key: CryptoKey) {
        const db = await this.db;

        await db.put('keys', key, alias);
    }
    
    async deleteCryptoKeyPair(alias: string) {
        const db = await this.db;

        await db.delete('keyPairs', alias);
    }

    async deleteCryptoKey(alias: string) {
        const db = await this.db;

        await db.delete('keys', alias);
    }
}