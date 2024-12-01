package com.lagoware.capacitorkeymanager;

import android.util.Base64;

import com.getcapacitor.JSObject;

public class RecoverableKeyPair {
    public RecoverableKey privateKey;
    public String publicKey;

    public RecoverableKeyPair(RecoverableKey privateKey, String publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public RecoverableKeyPair(RecoverableKey privateKey, byte[] publicKey) {
        this.privateKey = privateKey;
        this.publicKey = Base64.encodeToString(publicKey, Base64.NO_WRAP);
    }

    public RecoverableKeyPair(JSObject json) {
        JSObject privateKey = json.getJSObject("privateKey");

        assert privateKey != null;
        this.privateKey = new RecoverableKey(
            privateKey.getString("ciphertext"),
            privateKey.getString("iv"),
            privateKey.getString("salt")
        );
        this.publicKey = json.getString("publicKey");
    }

    public JSObject toJson() {
        JSObject keyPairJs = new JSObject();

        keyPairJs.put("publicKey", this.publicKey);
        keyPairJs.put("privateKey", this.privateKey.toJson());

        return keyPairJs;
    }
}
