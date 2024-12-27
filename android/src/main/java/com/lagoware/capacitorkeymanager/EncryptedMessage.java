package com.lagoware.capacitorkeymanager;

import android.util.Base64;

import com.getcapacitor.JSObject;
public class EncryptedMessage {
    public byte[] iv;
    public byte[] data;
    public EncryptedMessage(byte[] data, byte[] iv) {
        this.data = data;
        this.iv = iv;
    }
    public SerializedEncryptedMessage serialize() {
        return new SerializedEncryptedMessage(
            Base64.encodeToString(this.data, Base64.NO_WRAP),
            Base64.encodeToString(this.iv, Base64.NO_WRAP)
        );
    }
}
