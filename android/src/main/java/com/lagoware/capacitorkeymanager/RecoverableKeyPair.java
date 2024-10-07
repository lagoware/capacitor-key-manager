package com.lagoware.capacitorkeymanager;

public class RecoverableKeyPair {
    public RecoverableKey privateKey;
    public String publicKey;

    public RecoverableKeyPair(RecoverableKey privateKey, String publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }
}
