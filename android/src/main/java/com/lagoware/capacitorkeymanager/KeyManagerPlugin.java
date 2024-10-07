package com.lagoware.capacitorkeymanager;

import android.os.Build;

import androidx.annotation.RequiresApi;

import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

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

    private RecoverableKeyPair jsonToRecoverableKeyPair(JSObject json) {
        JSObject privateKey = json.getJSObject("privateKey");

        assert privateKey != null;

        return new RecoverableKeyPair(
            new RecoverableKey(
                privateKey.getString("ciphertext"),
                privateKey.getString("iv"),
                privateKey.getString("salt")
            ),
            json.getString("publicKey")
        );
    }

    private JSObject recoverableKeyToJson(RecoverableKey key) {
        JSObject keyJs = serializedEncryptedMessageToJson(key);

        keyJs.put("salt", key.salt);

        return keyJs;
    }

    private JSObject recoverableKeyPairToJson(RecoverableKeyPair keyPair) {
        JSObject keyPairJs = new JSObject();

        keyPairJs.put("publicKey", keyPair.publicKey);
        keyPairJs.put("privateKey", recoverableKeyToJson(keyPair.privateKey));

        return keyPairJs;
    }

    private JSObject serializedEncryptedMessageToJson(SerializedEncryptedMessage message) {
        JSObject keyJs = new JSObject();

        keyJs.put("ciphertext", message.ciphertext);
        keyJs.put("iv", message.iv);

        return keyJs;
    }

    private RecoverableKey jsonToRecoverableKey(JSObject json) {
        SerializedEncryptedMessage message = jsonToEncryptedMessage(json);

        return new RecoverableKey(
            message.ciphertext,
            message.iv,
            json.getString("salt")
        );
    }

    private SerializedEncryptedMessage jsonToEncryptedMessage(JSObject json) {
        return new SerializedEncryptedMessage(
            json.getString("ciphertext"),
            json.getString("iv")
        );
    }

    //    checkAliasExists(options: { keyAlias: string }): Promise<{ aliasExists: boolean }>;
    @PluginMethod
    public void checkAliasExists(PluginCall call) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        String keyAlias = call.getString("keyAlias");

        JSObject ret = new JSObject();

        Boolean aliasExists = implementation.checkAliasExists(keyAlias);

        ret.put("aliasExists", aliasExists);

        call.resolve(ret);
    }

    //    generateKey(options: { keyAlias: string }): Promise<void>;
    @RequiresApi(api = Build.VERSION_CODES.M)
    @PluginMethod
    public void generateKey(PluginCall call) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        String keyAlias = call.getString("keyAlias");

        implementation.generateKey(keyAlias);

        call.resolve();
    }

    //    generateRecoverableSignatureKeyPair(options: { alias: string, password: string, salt?: string }): Promise<{ recoverableKeyPair: RecoverableKeyPair}>;
    @RequiresApi(api = Build.VERSION_CODES.M)
    @PluginMethod
    public void generateRecoverableSignatureKeyPair(PluginCall call) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException, IOException, BadPaddingException, InvalidKeyException, OperatorCreationException {
        String password = call.getString("password");
        String salt = call.getString("salt");

        JSObject ret = new JSObject();

        if (salt == null) {
            ret.put("recoverableKeyPair", recoverableKeyPairToJson(implementation.generateRecoverableSignatureKeyPair(password)));
        } else {
            ret.put("recoverableKeyPair", recoverableKeyPairToJson(implementation.generateRecoverableSignatureKeyPair(password, salt)));
        }

        call.resolve(ret);
    }

    //    generateRecoverableAgreementKeyPair(options: { alias: string, password: string, salt?: string }): Promise<{ recoverableKeyPair: RecoverableKeyPair}>;
    @RequiresApi(api = Build.VERSION_CODES.S)
    @PluginMethod
    public void generateRecoverableAgreementKeyPair(PluginCall call) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException, IOException, BadPaddingException, InvalidKeyException, OperatorCreationException {
        String password = call.getString("password");
        String salt = call.getString("salt");

        JSObject ret = new JSObject();

        if (salt == null) {
            ret.put("recoverableKeyPair", recoverableKeyPairToJson(implementation.generateRecoverableAgreementKeyPair(password)));
        } else {
            ret.put("recoverableKeyPair", recoverableKeyPairToJson(implementation.generateRecoverableAgreementKeyPair(password, salt)));
        }
        call.resolve(ret);
    }

    //    generateRecoverableKey(options: { alias: string, password: string, salt?: string }): Promise<{ recoverableKey: RecoverableKey }>;
    @RequiresApi(api = Build.VERSION_CODES.M)
    @PluginMethod
    public void generateRecoverableKey(PluginCall call) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException, IOException, BadPaddingException, InvalidKeyException {
        String password = call.getString("password");
        String salt = call.getString("salt");

        JSObject ret = new JSObject();

        if (salt == null) {
            ret.put("recoverableKey", recoverableKeyToJson(implementation.generateRecoverableKey(password)));
        } else {
            ret.put("recoverableKey", recoverableKeyToJson(implementation.generateRecoverableKey(password, salt)));
        }
        call.resolve(ret);
    }

    //    reWrapSignatureKeyPair(options: { currentPassword: string, newPassword: string, newSalt?: string, recoverableKeyPair: RecoverableKeyPair }): Promise<{ recoverableKeyPair: RecoverableKeyPair }>;
    @RequiresApi(api = Build.VERSION_CODES.M)
    @PluginMethod
    public void reWrapSignatureKeyPair(PluginCall call) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        String currentPassword = call.getString("currentPassword");
        String newPassword = call.getString("newPassword");
        String newSalt = call.getString("newSalt");
        RecoverableKeyPair recoverableKeyPair = jsonToRecoverableKeyPair(call.getObject("recoverableKeyPair"));

        JSObject ret = new JSObject();

        if (newSalt == null) {
            ret.put("recoverableKeyPair", recoverableKeyPairToJson(implementation.reWrapSignatureKeyPair(recoverableKeyPair, currentPassword, newPassword)));
        } else {
            ret.put("recoverableKeyPair", recoverableKeyPairToJson(implementation.reWrapSignatureKeyPair(recoverableKeyPair, currentPassword, newPassword, newSalt)));
        }
        call.resolve(ret);
    }

    //    reWrapAgreementKeyPair(options: { currentPassword: string, newPassword: string, newSalt?: string, recoverableKeyPair: RecoverableKeyPair }): Promise<{ recoverableKeyPair: RecoverableKeyPair }>;
    @RequiresApi(api = Build.VERSION_CODES.M)
    @PluginMethod
    public void reWrapAgreementKeyPair(PluginCall call) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        String currentPassword = call.getString("currentPassword");
        String newPassword = call.getString("newPassword");
        String newSalt = call.getString("newSalt");
        RecoverableKeyPair recoverableKeyPair = jsonToRecoverableKeyPair(call.getObject("recoverableKeyPair"));

        JSObject ret = new JSObject();

        if (newSalt == null) {
            ret.put("recoverableKeyPair", recoverableKeyPairToJson(implementation.reWrapAgreementKeyPair(recoverableKeyPair, currentPassword, newPassword)));
        } else {
            ret.put("recoverableKeyPair", recoverableKeyPairToJson(implementation.reWrapAgreementKeyPair(recoverableKeyPair, currentPassword, newPassword, newSalt)));
        }
        call.resolve(ret);
    }

    //    reWrapKey(options: { currentPassword: string, newPassword: string, newSalt?: string, recoverableKey: RecoverableKey }): Promise<{ recoverableKey: RecoverableKey }>;
    @RequiresApi(api = Build.VERSION_CODES.M)
    @PluginMethod
    public void reWrapKey(PluginCall call) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        String currentPassword = call.getString("currentPassword");
        String newPassword = call.getString("newPassword");
        String newSalt = call.getString("newSalt");
        RecoverableKey recoverableKey = jsonToRecoverableKey(call.getObject("recoverableKeyPair"));

        JSObject ret = new JSObject();

        if (newSalt == null) {
            ret.put("recoverableKey", recoverableKeyToJson(implementation.reWrapKey(recoverableKey, currentPassword, newPassword)));
        } else {
            ret.put("recoverableKey", recoverableKeyToJson(implementation.reWrapKey(recoverableKey, currentPassword, newPassword, newSalt)));
        }
        call.resolve(ret);
    }

    //    importPublicSignatureKey(options: { alias: string, publicKey: string }): Promise<void>;
    @RequiresApi(api = Build.VERSION_CODES.S)
    @PluginMethod
    public void importPublicSignatureKey(PluginCall call) throws InvalidAlgorithmParameterException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, OperatorCreationException {
        String alias = call.getString("alias");
        String publicKey = call.getString("publicKey");

        implementation.importPublicSignatureKey(alias, publicKey);

        call.resolve();
    }

    //    importPublicAgreementKey(options: { alias: string, publicKey: string }): Promise<void>;
    @RequiresApi(api = Build.VERSION_CODES.S)
    @PluginMethod
    public void importPublicAgreementKey(PluginCall call) throws InvalidAlgorithmParameterException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, OperatorCreationException {
        String alias = call.getString("alias");
        String publicKey = call.getString("publicKey");

        implementation.importPublicAgreementKey(alias, publicKey);

        call.resolve();
    }

    //    recoverKey(options: { alias: string, recoverableKey: RecoverableKey, password: string }): Promise<void>;
    @RequiresApi(api = Build.VERSION_CODES.M)
    @PluginMethod
    public void recoverKey(PluginCall call) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        String alias = call.getString("alias");
        String password = call.getString("password");
        RecoverableKey recoverableKey = jsonToRecoverableKey(call.getObject("recoverableKey"));

        implementation.recoverKey(alias, recoverableKey, password);

        call.resolve();
    }

    //    recoverSignatureKeyPair(options: { alias: string, recoverableKeyPair: RecoverableKeyPair, password: string }): Promise<void>;
    @RequiresApi(api = Build.VERSION_CODES.M)
    @PluginMethod
    public void recoverSignatureKeyPair(PluginCall call) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException, IOException, BadPaddingException, InvalidKeyException, OperatorCreationException {
        String alias = call.getString("alias");
        String password = call.getString("password");
        RecoverableKeyPair recoverableKeyPair = jsonToRecoverableKeyPair(call.getObject("recoverableKeyPair"));

        implementation.recoverSignatureKeyPair(
            alias,
            recoverableKeyPair,
            password
        );

        call.resolve();
    }

    //    recoverAgreementKeyPair(options: { alias: string, recoverableKeyPair: RecoverableKeyPair, password: string }): Promise<void>;
    @RequiresApi(api = Build.VERSION_CODES.S)
    @PluginMethod
    public void recoverAgreementKeyPair(PluginCall call) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException, IOException, BadPaddingException, InvalidKeyException, OperatorCreationException {
        String alias = call.getString("alias");
        String password = call.getString("password");
        RecoverableKeyPair recoverableKeyPair = jsonToRecoverableKeyPair(call.getObject("recoverableKeyPair"));

        implementation.recoverAgreementKeyPair(
            alias,
            recoverableKeyPair,
            password
        );

        call.resolve();
    }

    //    encrypt(options: { keyAlias: string, cleartext: string }): Promise<{ encryptedMessage: EncryptedMessage }>;
    @PluginMethod
    public void encrypt(PluginCall call) throws InvalidAlgorithmParameterException, UnrecoverableEntryException, NoSuchPaddingException, IllegalBlockSizeException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String keyAlias = call.getString("keyAlias");
        String cleartext = call.getString("cleartext");

        JSObject ret = new JSObject();

        ret.put("encryptedMessage", serializedEncryptedMessageToJson(implementation.encrypt(keyAlias, cleartext)));

        call.resolve(ret);
    }

    //    decrypt(options: { keyAlias: string, encryptedMessage: EncryptedMessage }): Promise<{ cleartext: string }>;
    @PluginMethod
    public void decrypt(PluginCall call) throws InvalidAlgorithmParameterException, UnrecoverableEntryException, NoSuchPaddingException, IllegalBlockSizeException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String keyAlias = call.getString("keyAlias");
        JSObject encryptedMessage = call.getObject("encryptedMessage");

        JSObject ret = new JSObject();

        ret.put(
            "cleartext",
            implementation.decrypt(
                keyAlias,
                jsonToEncryptedMessage(encryptedMessage)
            )
        );

        call.resolve(ret);
    }

    //    encryptWithAgreedKey(options: { privateKeyAlias: string, publicKeyAlias: string, cleartext: string, info?: string }): Promise<{ encryptedMessage: EncryptedMessage }>;
    @RequiresApi(api = Build.VERSION_CODES.M)
    @PluginMethod
    public void encryptWithAgreedKey(PluginCall call) throws GeneralSecurityException, IOException {
        String privateKeyAlias = call.getString("privateKeyAlias");
        String publicKeyAlias = call.getString("publicKeyAlias");
        String cleartext = call.getString("cleartext");
        String info = call.getString("info");

        JSObject ret = new JSObject();

        SerializedEncryptedMessage encryptedMessage = null;

        if (info == null) {
            encryptedMessage = implementation.encryptWithAgreedKey(privateKeyAlias, publicKeyAlias, cleartext);
        } else {
            encryptedMessage = implementation.encryptWithAgreedKey(privateKeyAlias, publicKeyAlias, cleartext, info);
        }

        ret.put(
            "encryptedMessage",
            serializedEncryptedMessageToJson(encryptedMessage)
        );

        call.resolve(ret);
    }

    //    decryptWithAgreedKey(options: { privateKeyAlias: string, publicKeyAlias: string, encryptedMessage: EncryptedMessage, info?: string }): Promise<{ cleartext: string }>;
    @RequiresApi(api = Build.VERSION_CODES.M)
    @PluginMethod
    public void decryptWithAgreedKey(PluginCall call) throws GeneralSecurityException, IOException {
        String privateKeyAlias = call.getString("privateKeyAlias");
        String publicKeyAlias = call.getString("publicKeyAlias");
        JSObject encryptedMessage = call.getObject("encryptedMessage");
        String info = call.getString("info");

        JSObject ret = new JSObject();

        String cleartext = null;

        if (info == null) {
            cleartext = implementation.decryptWithAgreedKey(privateKeyAlias, publicKeyAlias, jsonToEncryptedMessage(encryptedMessage));
        } else {
            cleartext = implementation.decryptWithAgreedKey(privateKeyAlias, publicKeyAlias, jsonToEncryptedMessage(encryptedMessage), info);
        }

        ret.put("cleartext", cleartext);

        call.resolve(ret);
    }

    //    sign(options: { keyAlias: string, cleartext: string }): Promise<{ signature: string }>;
    @PluginMethod
    public void sign(PluginCall call) throws UnrecoverableEntryException, CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException, SignatureException, InvalidKeyException {
        String keyAlias = call.getString("keyAlias");
        String cleartext = call.getString("cleartext");

        assert cleartext != null;

        JSObject ret = new JSObject();

        ret.put("signature", implementation.sign(keyAlias, cleartext));

        call.resolve(ret);
    }

    //    verify(options: { keyAlias: string, cleartext: string, signature: string }): Promise<{ isValid: boolean }>;
    @PluginMethod
    public void verify(PluginCall call) throws UnrecoverableEntryException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        String keyAlias = call.getString("keyAlias");
        String cleartext = call.getString("cleartext");
        String signature = call.getString("signature");

        JSObject ret = new JSObject();

        ret.put("isValid", implementation.verify(keyAlias, cleartext, signature));

        call.resolve(ret);
    }

}
