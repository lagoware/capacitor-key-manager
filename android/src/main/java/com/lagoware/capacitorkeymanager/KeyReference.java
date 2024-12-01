package com.lagoware.capacitorkeymanager;

public class KeyReference extends EncryptionKeySpec {
    public String keyAlias;
    public String publicKeyAlias;

    public String info;

    public KeyReference(String keyAlias) {
        this.keyAlias = keyAlias;
        this.publicKeyAlias = null;
        this.info = null;
    }
    public KeyReference(String keyAlias, String publicKeyAlias) {
        this.keyAlias = keyAlias;
        this.publicKeyAlias = publicKeyAlias;
        this.info = null;
    }
    public KeyReference(String keyAlias, String publicKeyAlias, String info) {
        this.keyAlias = keyAlias;
        this.publicKeyAlias = publicKeyAlias;
        this.info = info;
    }
}
