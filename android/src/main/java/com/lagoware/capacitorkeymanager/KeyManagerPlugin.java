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

//    private RecoverableKeyPair jsonToRecoverableKeyPair(JSObject json) {
//        JSObject privateKey = json.getJSObject("privateKey");
//
//        assert privateKey != null;
//
//        return new RecoverableKeyPair(
//            new RecoverableKey(
//                privateKey.getString("ciphertext"),
//                privateKey.getString("iv"),
//                privateKey.getString("salt")
//            ),
//            json.getString("publicKey")
//        );
//    }
//
//    private JSObject recoverableKeyToJson(RecoverableKey key) {
//        JSObject keyJs = serializedEncryptedMessageToJson(key);
//
//        keyJs.put("salt", key.salt);
//
//        return keyJs;
//    }
//
//    private JSObject recoverableKeyPairToJson(RecoverableKeyPair keyPair) {
//        JSObject keyPairJs = new JSObject();
//
//        keyPairJs.put("publicKey", keyPair.publicKey);
//        keyPairJs.put("privateKey", recoverableKeyToJson(keyPair.privateKey));
//
//        return keyPairJs;
//    }
//
//    private JSObject serializedEncryptedMessageToJson(SerializedEncryptedMessage message) {
//
//    }
//
//    private RecoverableKey jsonToRecoverableKey(JSObject json) {
//        SerializedEncryptedMessage message = jsonToEncryptedMessage(json);
//
//        return new RecoverableKey(
//            message.ciphertext,
//            message.iv,
//            json.getString("salt")
//        );
//    }

//    private SerializedEncryptedMessage jsonToEncryptedMessage(JSObject json) {
//        return new SerializedEncryptedMessage(
//            json.getString("ciphertext"),
//            json.getString("iv")
//        );
//    }

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

    @RequiresApi(api = Build.VERSION_CODES.M)
    @PluginMethod
    public void generateRecoverableSignatureKeyPair(PluginCall call) throws GeneralSecurityException, IOException, OperatorCreationException {
        EncryptionKeySpec spec = EncryptionKeySpec.fromJson(call.getData());

        JSObject ret = new JSObject();

        ret.put("recoverableKeyPair", implementation.generateRecoverableSignatureKeyPair(spec).toJson());

        call.resolve(ret);
    }

    @RequiresApi(api = Build.VERSION_CODES.S)
    @PluginMethod
    public void generateRecoverableAgreementKeyPair(PluginCall call) throws GeneralSecurityException, IOException, OperatorCreationException {
        EncryptionKeySpec spec = EncryptionKeySpec.fromJson(call.getData());

        JSObject ret = new JSObject();

        ret.put("recoverableKeyPair", implementation.generateRecoverableAgreementKeyPair(spec).toJson());

        call.resolve(ret);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @PluginMethod
    public void generateRecoverableKey(PluginCall call) throws GeneralSecurityException, IOException {
        EncryptionKeySpec spec = EncryptionKeySpec.fromJson(call.getData());

        JSObject ret = new JSObject();

        ret.put("recoverableKey", implementation.generateRecoverableKey(spec).toJson());

        call.resolve(ret);
    }

    //    rewrapSignatureKeyPair(options: { currentPassword: string, newPassword: string, newSalt?: string, recoverableKeyPair: RecoverableKeyPair }): Promise<{ recoverableKeyPair: RecoverableKeyPair }>;
    @RequiresApi(api = Build.VERSION_CODES.M)
    @PluginMethod
    public void rewrapSignatureKeyPair(PluginCall call) throws GeneralSecurityException, IOException {
        EncryptionKeySpec unwrapWith = EncryptionKeySpec.fromJson(call.getObject("unwrapWith"));
        EncryptionKeySpec rewrapWith = EncryptionKeySpec.fromJson(call.getObject("rewrapWith"));

        RecoverableKeyPair recoverableKeyPair = new RecoverableKeyPair(call.getObject("recoverableKeyPair"));

        JSObject ret = new JSObject();

        ret.put("recoverableKeyPair", implementation.rewrapSignatureKeyPair(recoverableKeyPair, unwrapWith, rewrapWith).toJson());

        call.resolve(ret);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @PluginMethod
    public void rewrapAgreementKeyPair(PluginCall call) throws GeneralSecurityException, IOException {
        EncryptionKeySpec unwrapWith = EncryptionKeySpec.fromJson(call.getObject("unwrapWith"));
        EncryptionKeySpec rewrapWith = EncryptionKeySpec.fromJson(call.getObject("rewrapWith"));

        RecoverableKeyPair recoverableKeyPair = new RecoverableKeyPair(call.getObject("recoverableKeyPair"));

        JSObject ret = new JSObject();

        ret.put("recoverableKeyPair", implementation.rewrapAgreementKeyPair(recoverableKeyPair, unwrapWith, rewrapWith).toJson());

        call.resolve(ret);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @PluginMethod
    public void rewrapKey(PluginCall call) throws GeneralSecurityException, IOException {
        EncryptionKeySpec unwrapWith = EncryptionKeySpec.fromJson(call.getObject("unwrapWith"));
        EncryptionKeySpec rewrapWith = EncryptionKeySpec.fromJson(call.getObject("rewrapWith"));

        RecoverableKey recoverableKey = new RecoverableKey(call.getObject("recoverableKey"));

        JSObject ret = new JSObject();

        ret.put("recoverableKey", implementation.rewrapKey(recoverableKey, unwrapWith, rewrapWith).toJson());

        call.resolve(ret);
    }

    @RequiresApi(api = Build.VERSION_CODES.S)
    @PluginMethod
    public void importPublicSignatureKey(PluginCall call) throws InvalidAlgorithmParameterException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, OperatorCreationException {
        String alias = call.getString("alias");
        String publicKey = call.getString("publicKey");

        implementation.importPublicSignatureKey(alias, publicKey);

        call.resolve();
    }

    @RequiresApi(api = Build.VERSION_CODES.S)
    @PluginMethod
    public void importPublicAgreementKey(PluginCall call) throws InvalidAlgorithmParameterException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, OperatorCreationException {
        String alias = call.getString("alias");
        String publicKey = call.getString("publicKey");

        implementation.importPublicAgreementKey(alias, publicKey);

        call.resolve();
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @PluginMethod
    public void recoverKey(PluginCall call) throws GeneralSecurityException, IOException {
        String alias = call.getString("importAlias");
        EncryptionKeySpec unwrapWith = EncryptionKeySpec.fromJson(call.getObject("unwrapWith"));
        RecoverableKey recoverableKey = new RecoverableKey(call.getObject("recoverableKey"));

        implementation.recoverKey(alias, recoverableKey, unwrapWith);

        call.resolve();
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @PluginMethod
    public void recoverSignatureKeyPair(PluginCall call) throws GeneralSecurityException, IOException, OperatorCreationException {
        String alias = call.getString("importAlias");
        EncryptionKeySpec unwrapWith = EncryptionKeySpec.fromJson(call.getObject("unwrapWith"));
        RecoverableKeyPair recoverableKeyPair = new RecoverableKeyPair(call.getObject("recoverableKeyPair"));

        implementation.recoverSignatureKeyPair(alias, recoverableKeyPair, unwrapWith);

        call.resolve();
    }

    @RequiresApi(api = Build.VERSION_CODES.S)
    @PluginMethod
    public void recoverAgreementKeyPair(PluginCall call) throws GeneralSecurityException, IOException, OperatorCreationException {
        String alias = call.getString("importAlias");
        EncryptionKeySpec unwrapWith = EncryptionKeySpec.fromJson(call.getObject("unwrapWith"));
        RecoverableKeyPair recoverableKeyPair = new RecoverableKeyPair(call.getObject("recoverableKeyPair"));

        implementation.recoverAgreementKeyPair(alias, recoverableKeyPair, unwrapWith);

        call.resolve();
    }

    @PluginMethod
    public void encrypt(PluginCall call) throws GeneralSecurityException, IOException {
        EncryptionKeySpec encryptWith = EncryptionKeySpec.fromJson(call.getObject("encryptWith"));
        String cleartext = call.getString("cleartext");

        JSObject ret = new JSObject();

        ret.put("encryptedMessage", implementation.encrypt(encryptWith, cleartext).toJson());

        call.resolve(ret);
    }

    @PluginMethod
    public void decrypt(PluginCall call) throws GeneralSecurityException, IOException {
        EncryptionKeySpec decryptWith = EncryptionKeySpec.fromJson(call.getObject("decryptWith"));
        SerializedEncryptedMessage encryptedMessage = new SerializedEncryptedMessage(call.getObject("encryptedMessage"));

        JSObject ret = new JSObject();

        ret.put("cleartext", implementation.decrypt(decryptWith, encryptedMessage));

        call.resolve(ret);
    }

    @PluginMethod
    public void sign(PluginCall call) throws UnrecoverableEntryException, CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException, SignatureException, InvalidKeyException {
        String keyAlias = call.getString("keyAlias");
        String cleartext = call.getString("cleartext");

        assert cleartext != null;

        JSObject ret = new JSObject();

        ret.put("signature", implementation.sign(keyAlias, cleartext));

        call.resolve(ret);
    }

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
