package com.lagoware.capacitorkeymanager;

import android.os.Build;

import androidx.annotation.RequiresApi;

import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import org.bouncycastle.openssl.EncryptionException;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

@CapacitorPlugin(name = "KeyManager")
public class KeyManagerPlugin extends Plugin {

    private final KeyManager implementation = new KeyManager();
    @PluginMethod
    public void checkAliasExists(PluginCall call) {
        String keyAlias = call.getString("keyAlias");

        JSObject ret = new JSObject();

        try {
            Boolean aliasExists = implementation.checkAliasExists(keyAlias);
            ret.put("aliasExists", aliasExists);
            call.resolve(ret);
        } catch (RuntimeException | CertificateException | KeyStoreException | IOException |
                 NoSuchAlgorithmException | NoSuchProviderException error) {
            call.reject(error.getMessage());
        }
    }
    @RequiresApi(api = Build.VERSION_CODES.M)
    @PluginMethod
    public void generateKey(PluginCall call) {
        String keyAlias = call.getString("keyAlias");

        try {
            implementation.generateKey(keyAlias);
            call.resolve();
        } catch (RuntimeException | NoSuchAlgorithmException | InvalidAlgorithmParameterException |
                 NoSuchProviderException error) {
            call.reject(error.getMessage());
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @PluginMethod
    public void generateRecoverableSignatureKeyPair(PluginCall call) {
        EncryptionKeySpec spec = EncryptionKeySpec.fromJson(call.getData());

        JSObject ret = new JSObject();

        try {
            ret.put("recoverableKeyPair", implementation.generateRecoverableSignatureKeyPair(spec).toJson());
            call.resolve(ret);
        } catch (RuntimeException | GeneralSecurityException | IOException error) {
            call.reject(error.getMessage());
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.S)
    @PluginMethod
    public void generateRecoverableAgreementKeyPair(PluginCall call) {
        EncryptionKeySpec spec = EncryptionKeySpec.fromJson(call.getData());

        JSObject ret = new JSObject();

        try {
            ret.put("recoverableKeyPair", implementation.generateRecoverableAgreementKeyPair(spec).toJson());
            call.resolve(ret);
        } catch (RuntimeException | GeneralSecurityException | IOException error) {
            call.reject(error.getMessage());
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @PluginMethod
    public void generateRecoverableKey(PluginCall call) {
        EncryptionKeySpec spec = EncryptionKeySpec.fromJson(call.getData());

        JSObject ret = new JSObject();

        try {
            ret.put("recoverableKey", implementation.generateRecoverableKey(spec).toJson());
            call.resolve(ret);
        } catch (RuntimeException | GeneralSecurityException | IOException error) {
            call.reject(error.getMessage());
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @PluginMethod
    public void rewrapSignatureKeyPair(PluginCall call) {
        EncryptionKeySpec unwrapWith = EncryptionKeySpec.fromJson(call.getObject("unwrapWith"));
        EncryptionKeySpec rewrapWith = EncryptionKeySpec.fromJson(call.getObject("rewrapWith"));

        RecoverableKeyPair recoverableKeyPair = new RecoverableKeyPair(call.getObject("recoverableKeyPair"));

        JSObject ret = new JSObject();

        try {
            ret.put("recoverableKeyPair", implementation.rewrapSignatureKeyPair(recoverableKeyPair, unwrapWith, rewrapWith).toJson());
            call.resolve(ret);
        } catch (RuntimeException | GeneralSecurityException | IOException error) {
            call.reject(error.getMessage());
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @PluginMethod
    public void rewrapAgreementKeyPair(PluginCall call) {
        EncryptionKeySpec unwrapWith = EncryptionKeySpec.fromJson(call.getObject("unwrapWith"));
        EncryptionKeySpec rewrapWith = EncryptionKeySpec.fromJson(call.getObject("rewrapWith"));

        RecoverableKeyPair recoverableKeyPair = new RecoverableKeyPair(call.getObject("recoverableKeyPair"));

        JSObject ret = new JSObject();

        try {
            ret.put("recoverableKeyPair", implementation.rewrapAgreementKeyPair(recoverableKeyPair, unwrapWith, rewrapWith).toJson());
            call.resolve(ret);
        } catch (RuntimeException | GeneralSecurityException | IOException error) {
            call.reject(error.getMessage());
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @PluginMethod
    public void rewrapKey(PluginCall call) {
        EncryptionKeySpec unwrapWith = EncryptionKeySpec.fromJson(call.getObject("unwrapWith"));
        EncryptionKeySpec rewrapWith = EncryptionKeySpec.fromJson(call.getObject("rewrapWith"));

        RecoverableKey recoverableKey = new RecoverableKey(call.getObject("recoverableKey"));

        JSObject ret = new JSObject();
        try {
            ret.put("recoverableKey", implementation.rewrapKey(recoverableKey, unwrapWith, rewrapWith).toJson());
            call.resolve(ret);
        } catch (RuntimeException | GeneralSecurityException | IOException error) {
            call.reject(error.getMessage());
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.S)
    @PluginMethod
    public void importPublicSignatureKey(PluginCall call) {
        String alias = call.getString("alias");
        String publicKey = call.getString("publicKey");

        try {
            implementation.importPublicSignatureKey(alias, publicKey);
            call.resolve();
        } catch (RuntimeException | InvalidAlgorithmParameterException | CertificateException |
                 KeyStoreException | IOException | NoSuchAlgorithmException |
                 InvalidKeySpecException | OperatorCreationException | NoSuchProviderException error) {
            call.reject(error.getMessage());
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.S)
    @PluginMethod
    public void importPublicAgreementKey(PluginCall call) {
        String alias = call.getString("alias");
        String publicKey = call.getString("publicKey");

        try {
            implementation.importPublicAgreementKey(alias, publicKey);
            call.resolve();
        } catch (RuntimeException | InvalidAlgorithmParameterException | CertificateException |
                 KeyStoreException | IOException | NoSuchAlgorithmException |
                 InvalidKeySpecException | OperatorCreationException | NoSuchProviderException error) {
            call.reject(error.getMessage());
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @PluginMethod
    public void recoverKey(PluginCall call) {
        String alias = call.getString("importAlias");
        EncryptionKeySpec unwrapWith = EncryptionKeySpec.fromJson(call.getObject("unwrapWith"));
        RecoverableKey recoverableKey = new RecoverableKey(call.getObject("recoverableKey"));

        try {
            implementation.recoverKey(alias, recoverableKey, unwrapWith);
            call.resolve();
        } catch (RuntimeException | GeneralSecurityException | IOException error) {
            call.reject(error.getMessage());
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @PluginMethod
    public void recoverSignatureKeyPair(PluginCall call) {
        String alias = call.getString("importAlias");
        EncryptionKeySpec unwrapWith = EncryptionKeySpec.fromJson(call.getObject("unwrapWith"));
        RecoverableKeyPair recoverableKeyPair = new RecoverableKeyPair(call.getObject("recoverableKeyPair"));

        try {
            implementation.recoverSignatureKeyPair(alias, recoverableKeyPair, unwrapWith);
            call.resolve();
        } catch (RuntimeException | GeneralSecurityException | IOException | OperatorCreationException error) {
            call.reject(error.getMessage());
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.S)
    @PluginMethod
    public void recoverAgreementKeyPair(PluginCall call) {
        String alias = call.getString("importAlias");
        EncryptionKeySpec unwrapWith = EncryptionKeySpec.fromJson(call.getObject("unwrapWith"));
        RecoverableKeyPair recoverableKeyPair = new RecoverableKeyPair(call.getObject("recoverableKeyPair"));

        try {
            implementation.recoverAgreementKeyPair(alias, recoverableKeyPair, unwrapWith);
            call.resolve();
        } catch (RuntimeException | GeneralSecurityException | IOException | OperatorCreationException error) {
            call.reject(error.getMessage());
        }
    }

    @PluginMethod
    public void encrypt(PluginCall call) {
        EncryptionKeySpec encryptWith = EncryptionKeySpec.fromJson(call.getObject("encryptWith"));
        String cleartext = call.getString("cleartext");

        JSObject ret = new JSObject();

        try {
            ret.put("encryptedMessage", implementation.encrypt(encryptWith, cleartext).toJson());
            call.resolve(ret);
        } catch (RuntimeException | GeneralSecurityException | IOException error) {
            call.reject(error.getMessage());
        }
    }

    @PluginMethod
    public void decrypt(PluginCall call) {
        EncryptionKeySpec decryptWith = EncryptionKeySpec.fromJson(call.getObject("decryptWith"));
        SerializedEncryptedMessage encryptedMessage = new SerializedEncryptedMessage(call.getObject("encryptedMessage"));

        JSObject ret = new JSObject();

        try {
            ret.put("cleartext", implementation.decrypt(decryptWith, encryptedMessage));
            call.resolve(ret);
        } catch (RuntimeException | GeneralSecurityException | IOException error) {
            call.reject(error.getMessage());
        }
    }

    @PluginMethod
    public void sign(PluginCall call) {
        String keyAlias = call.getString("keyAlias");
        String cleartext = call.getString("cleartext");

        assert cleartext != null;

        JSObject ret = new JSObject();

        try {
            ret.put("signature", implementation.sign(keyAlias, cleartext));
            call.resolve(ret);
        } catch (RuntimeException | KeyStoreException | UnrecoverableEntryException |
                 NoSuchAlgorithmException | CertificateException | IOException |
                 InvalidKeyException | SignatureException | NoSuchProviderException error) {
            call.reject(error.getMessage());
        }
    }

    @PluginMethod
    public void verify(PluginCall call) {
        String keyAlias = call.getString("keyAlias");
        String cleartext = call.getString("cleartext");
        String signature = call.getString("signature");

        JSObject ret = new JSObject();

        try {
            ret.put("isValid", implementation.verify(keyAlias, cleartext, signature));
            call.resolve(ret);
        } catch (RuntimeException | KeyStoreException | CertificateException | IOException |
                 NoSuchAlgorithmException | UnrecoverableEntryException | SignatureException |
                 InvalidKeyException | NoSuchProviderException | AssertionError error) {
            call.reject(error.getMessage());
        }
    }
}
