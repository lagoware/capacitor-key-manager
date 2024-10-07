package com.lagoware.capacitorkeymanager;

public class EncryptedMessage {
    public byte[] iv;
    public byte[] data;

    public EncryptedMessage(byte[] data, byte[] iv) {
        this.data = data;
        this.iv = iv;
    }
}
