package com.lagoware.capacitorkeymanager;

import android.util.Base64;

import com.getcapacitor.JSObject;

public class SerializedEncryptedMessage {
    public String iv;
    public String ciphertext;

    public SerializedEncryptedMessage(String ciphertext, String iv) {
        this.ciphertext = ciphertext;
        this.iv = iv;
    }

    public SerializedEncryptedMessage(byte[] ciphertext, byte[] iv) {
        this.ciphertext = Base64.encodeToString(ciphertext, Base64.NO_WRAP);
        this.iv = Base64.encodeToString(iv, Base64.NO_WRAP);
    }

    public EncryptedMessage deserialize() {
        return new EncryptedMessage(
            Base64.decode(this.ciphertext, Base64.NO_WRAP),
            Base64.decode(this.iv, Base64.NO_WRAP)
        );
    }

    public SerializedEncryptedMessage(JSObject json) {
        this.ciphertext = json.getString("ciphertext");
        this.iv = json.getString("iv");
    }

    public JSObject toJson() {
        JSObject keyJs = new JSObject();

        keyJs.put("ciphertext", this.ciphertext);
        keyJs.put("iv", this.iv);

        return keyJs;
    }
}
