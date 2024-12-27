package com.lagoware.capacitorkeymanager;

import com.getcapacitor.JSObject;


//export type DerivedKeyReference = SymmetricKeyReference & { publicKeyAlias: string, info?: string };
//export type SymmetricKeyReference = { keyAlias: string };
//export type KeyReference = SymmetricKeyReference |
//DerivedKeyReference;
//
//export type PasswordParams = { password: string };
//export type PasswordParamsMaybeSalt = { password: string, salt?: string };
//export type PasswordParamsWithSalt = { password: string, salt: string }
public abstract class EncryptionKeySpec {
    static EncryptionKeySpec fromJson(JSObject json) {
        String password = json.getString("password", null);

        if (password != null) {
            return new PasswordWrappingParams(
                password,
                json.getString("salt", null)
            );
        } else {
            return new KeyReference(
                json.getString("keyAlias"),
                json.getString("publicKeyAlias", null),
                json.getString("info", null)
            );
        }
    }
}