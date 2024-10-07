package com.lagoware.capacitorkeymanager;

public class RecoverableKey extends SerializedEncryptedMessage {
    public String salt;

    public RecoverableKey(String ciphertext, String iv, String salt) {
        super(ciphertext, iv);
        this.salt = salt;
    }
}
