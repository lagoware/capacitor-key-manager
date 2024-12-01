package com.lagoware.capacitorkeymanager;

import android.util.Base64;

import com.getcapacitor.JSObject;

public class RecoverableKey extends SerializedEncryptedMessage {
    public String salt;

    public RecoverableKey(String ciphertext, String iv, String salt) {
        super(ciphertext, iv);
        this.salt = salt;
    }

    public RecoverableKey(String ciphertext, String iv) {
        super(ciphertext, iv);
        this.salt = null;
    }

    public RecoverableKey(byte[] ciphertext, byte[] iv) {
        super(ciphertext, iv);
        this.salt = null;
    }

    public RecoverableKey(EncryptedMessage message, String salt) {
        super(message.data, message.iv);
        this.salt = salt;
    }

    public RecoverableKey(EncryptedMessage message, byte[] salt) {
        super(message.data, message.iv);
        this.salt = Base64.encodeToString(salt, Base64.NO_WRAP);
    }

    public RecoverableKey(EncryptedMessage message) {
        super(message.data, message.iv);
        this.salt = null;
    }

    public RecoverableKey(JSObject json) {
        super(json);
        this.salt = json.getString("salt");
    }

    public JSObject toJson() {
        JSObject keyJs = super.toJson();

        keyJs.put("salt", this.salt);

        return keyJs;
    }
}
