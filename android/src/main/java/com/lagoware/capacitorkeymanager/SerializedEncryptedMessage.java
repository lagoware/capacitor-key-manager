package com.lagoware.capacitorkeymanager;

public class SerializedEncryptedMessage {
    public String iv;
    public String ciphertext;

    public SerializedEncryptedMessage(String ciphertext, String iv) {
        this.ciphertext = ciphertext;
        this.iv = iv;
    }
}
