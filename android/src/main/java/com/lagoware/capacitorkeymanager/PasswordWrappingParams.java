package com.lagoware.capacitorkeymanager;

import android.util.Base64;

import java.security.SecureRandom;

public class PasswordWrappingParams extends EncryptionKeySpec {

    public String password;
    public byte[] salt;

    public byte[] fillSalt() {
        if (this.salt == null) {
            byte[] salt = new byte[128];

            SecureRandom secRandom = new SecureRandom();
            secRandom.nextBytes(salt);

            this.salt = salt;
        }
        return this.salt;
    }

    public byte[] fillSalt(String salt) {
        if (this.salt == null) {
            this.salt = Base64.decode(salt, Base64.NO_WRAP);
        }
        return this.salt;
    }

    public PasswordWrappingParams(String password) {
        this.password = password;
        this.salt = null;
    }

    public PasswordWrappingParams(String password, String salt) {
        this.password = password;
        this.salt = salt != null
            ? Base64.decode(salt, Base64.NO_WRAP)
            : null;
    }

}
