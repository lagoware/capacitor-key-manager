package com.lagoware.capacitorkeymanager;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.util.Base64;
import com.google.crypto.tink.subtle.Hkdf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;

import javax.crypto.KeyAgreement;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;

import android.util.Log;

import androidx.annotation.RequiresApi;

import java.security.SecureRandom;

public class KeyManager {
    public static final String TAG = "KeyManager";

    @RequiresApi(api = Build.VERSION_CODES.M)
    public RecoverableKeyPair generateRecoverableSignatureKeyPair(String password) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException, IOException, BadPaddingException, InvalidKeyException, OperatorCreationException {
        return generateRecoverableSignatureKeyPair(password, generateSalt());
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public RecoverableKeyPair generateRecoverableSignatureKeyPair(String password, String salt) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException, IOException, BadPaddingException, InvalidKeyException, OperatorCreationException {
        return generateRecoverableSignatureKeyPair(password, Base64.decode(salt, Base64.NO_WRAP));
    }

    @RequiresApi(api = Build.VERSION_CODES.S)
    public RecoverableKeyPair generateRecoverableAgreementKeyPair(String password) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, KeyStoreException, CertificateException, IOException, OperatorCreationException {
        return generateRecoverableAgreementKeyPair(password, generateSalt());
    }

    @RequiresApi(api = Build.VERSION_CODES.S)
    public RecoverableKeyPair generateRecoverableAgreementKeyPair(String password, String salt) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, KeyStoreException, CertificateException, IOException, OperatorCreationException {
        return generateRecoverableAgreementKeyPair(password, Base64.decode(salt, Base64.NO_WRAP));
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public RecoverableKey generateRecoverableKey(String password, String salt) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, KeyStoreException, IOException, InvalidKeyException {
        return generateRecoverableKey(password, Base64.decode(salt, Base64.NO_WRAP));
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public RecoverableKey generateRecoverableKey(String password) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, CertificateException, KeyStoreException, IOException {
        return generateRecoverableKey(password, generateSalt());
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public void generateKey(String keyAlias) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        keyGenerator.init(
            new KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build()
        );

        keyGenerator.generateKey();
    }

    public Boolean checkAliasExists(String keyAlias) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        KeyStore ks = loadKeyStore();

        return ks.containsAlias(keyAlias);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public RecoverableKeyPair reWrapSignatureKeyPair(RecoverableKeyPair recoverableKeyPair, String currentPassword, String newPassword) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        PrivateKey privateKey = unwrapPrivateKey(
            Base64.decode(recoverableKeyPair.privateKey.ciphertext, Base64.NO_WRAP),
            Base64.decode(recoverableKeyPair.privateKey.iv, Base64.NO_WRAP),
            generatePasswordKey(currentPassword, recoverableKeyPair.privateKey.salt)
        );

        return new RecoverableKeyPair(
            keyToRecoverableKey(privateKey, newPassword, generateSalt()),
            recoverableKeyPair.publicKey
        );
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public RecoverableKeyPair reWrapSignatureKeyPair(RecoverableKeyPair recoverableKeyPair, String currentPassword, String newPassword, String newSalt) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        PrivateKey privateKey = unwrapPrivateKey(
            Base64.decode(recoverableKeyPair.privateKey.ciphertext, Base64.NO_WRAP),
            Base64.decode(recoverableKeyPair.privateKey.iv, Base64.NO_WRAP),
            generatePasswordKey(currentPassword, recoverableKeyPair.privateKey.salt)
        );

        return new RecoverableKeyPair(
            keyToRecoverableKey(privateKey, newPassword, Base64.decode(newSalt, Base64.NO_WRAP)),
            recoverableKeyPair.publicKey
        );
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public RecoverableKeyPair reWrapAgreementKeyPair(RecoverableKeyPair recoverableKeyPair, String currentPassword, String newPassword) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        PrivateKey privateKey = unwrapPrivateKey(
            Base64.decode(recoverableKeyPair.privateKey.ciphertext, Base64.NO_WRAP),
            Base64.decode(recoverableKeyPair.privateKey.iv, Base64.NO_WRAP),
            generatePasswordKey(currentPassword, recoverableKeyPair.privateKey.salt)
        );

        return new RecoverableKeyPair(
            keyToRecoverableKey(privateKey, newPassword, generateSalt()),
            recoverableKeyPair.publicKey
        );
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public RecoverableKeyPair reWrapAgreementKeyPair(RecoverableKeyPair recoverableKeyPair, String currentPassword, String newPassword, String newSalt) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        PrivateKey privateKey = unwrapPrivateKey(
            Base64.decode(recoverableKeyPair.privateKey.ciphertext, Base64.NO_WRAP),
            Base64.decode(recoverableKeyPair.privateKey.iv, Base64.NO_WRAP),
            generatePasswordKey(currentPassword, recoverableKeyPair.privateKey.salt)
        );

        return new RecoverableKeyPair(
            keyToRecoverableKey(privateKey, newPassword, Base64.decode(newSalt, Base64.NO_WRAP)),
            recoverableKeyPair.publicKey
        );
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public RecoverableKey reWrapKey(RecoverableKey recoverableKey, String currentPassword, String newPassword) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        SecretKey secretKey = unwrapSecretKey(
            Base64.decode(recoverableKey.ciphertext, Base64.NO_WRAP),
            Base64.decode(recoverableKey.iv, Base64.NO_WRAP),
            generatePasswordKey(currentPassword, recoverableKey.salt)
        );

        return keyToRecoverableKey(secretKey, newPassword, generateSalt());
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public RecoverableKey reWrapKey(RecoverableKey recoverableKey, String currentPassword, String newPassword, String newSalt) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        SecretKey secretKey = unwrapSecretKey(
            Base64.decode(recoverableKey.ciphertext, Base64.NO_WRAP),
            Base64.decode(recoverableKey.iv, Base64.NO_WRAP),
            generatePasswordKey(currentPassword, recoverableKey.salt)
        );

        return keyToRecoverableKey(secretKey, newPassword, Base64.decode(newSalt, Base64.NO_WRAP));
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public void recoverSignatureKeyPair(String alias, RecoverableKeyPair recoverableKeyPair, String password) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException, OperatorCreationException {
        recoverKeyPair(alias, recoverableKeyPair, password, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY);
    }

    @RequiresApi(api = Build.VERSION_CODES.S)
    public void recoverAgreementKeyPair(String alias, RecoverableKeyPair recoverableKeyPair, String password) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException, OperatorCreationException {
        recoverKeyPair(alias, recoverableKeyPair, password, KeyProperties.PURPOSE_AGREE_KEY);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public void recoverKey(String alias, RecoverableKey recoverableKey, String password) throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        KeyStore ks = loadKeyStore();

        ks.setEntry(
            alias,
            new KeyStore.SecretKeyEntry(
                unwrapSecretKey(
                    Base64.decode(recoverableKey.ciphertext, Base64.NO_WRAP),
                    Base64.decode(recoverableKey.iv, Base64.NO_WRAP),
                    generatePasswordKey(password, recoverableKey.salt)
                )
            ),
            new KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build()
        );
    }

    @RequiresApi(api = Build.VERSION_CODES.S)
    public void importPublicSignatureKey(String alias, String publicKey) throws InvalidAlgorithmParameterException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, OperatorCreationException {
        importPublicKey(alias, publicKey, KeyProperties.PURPOSE_VERIFY);
    }

    @RequiresApi(api = Build.VERSION_CODES.S)
    public void importPublicAgreementKey(String alias, String publicKey) throws InvalidAlgorithmParameterException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, OperatorCreationException {
        importPublicKey(alias, publicKey, KeyProperties.PURPOSE_AGREE_KEY);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public SerializedEncryptedMessage encryptWithAgreedKey(String privateKeyAlias, String publicKeyAlias, String cleartext, String info) throws GeneralSecurityException, IOException {
        byte[] sharedSecret = deriveAgreedKey(privateKeyAlias, publicKeyAlias);
        byte[] derivedSecret = deriveInfoKey(sharedSecret, info);
        SecretKey secretKey = new SecretKeySpec(derivedSecret, 0, 32, "AES/GCM/NoPadding");

        return serializeEncryptedMessage(encrypt(cleartext, secretKey));
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public SerializedEncryptedMessage encryptWithAgreedKey(String privateKeyAlias, String publicKeyAlias, String cleartext) throws GeneralSecurityException, IOException {
        byte[] sharedSecret = deriveAgreedKey(privateKeyAlias, publicKeyAlias);
        SecretKey secretKey = new SecretKeySpec(sharedSecret, 0, 32, "AES/GCM/NoPadding");

        return serializeEncryptedMessage(encrypt(cleartext, secretKey));
    }


    @RequiresApi(api = Build.VERSION_CODES.M)
    public String decryptWithAgreedKey(String privateKeyAlias, String publicKeyAlias, SerializedEncryptedMessage encryptedMessage, String info) throws GeneralSecurityException, IOException {
        byte[] sharedSecret = deriveAgreedKey(privateKeyAlias, publicKeyAlias);
        byte[] derivedSecret = deriveInfoKey(sharedSecret, info);
        SecretKey secretKey = new SecretKeySpec(derivedSecret, 0, 32, "AES/GCM/NoPadding");

        return decrypt(deserializeEncryptedMessage(encryptedMessage), secretKey);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public String decryptWithAgreedKey(String privateKeyAlias, String publicKeyAlias, SerializedEncryptedMessage encryptedMessage) throws GeneralSecurityException, IOException {
        byte[] sharedSecret = deriveAgreedKey(privateKeyAlias, publicKeyAlias);
        SecretKey secretKey = new SecretKeySpec(sharedSecret, 0, 32, "AES/GCM/NoPadding");

        return decrypt(deserializeEncryptedMessage(encryptedMessage), secretKey);
    }

    public SerializedEncryptedMessage encrypt(String alias, String cleartext) throws UnrecoverableEntryException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        return serializeEncryptedMessage(
            encrypt(
                cleartext,
                loadSecretKey(alias)
            )
        );
    }

    public String decrypt(String alias, SerializedEncryptedMessage message) throws UnrecoverableEntryException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        return decrypt(
            deserializeEncryptedMessage(message),
            loadSecretKey(alias)
        );
    }

    public String sign(String keyAlias, String cleartext) throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException, CertificateException, IOException, InvalidKeyException, SignatureException {
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(loadPrivateKey(keyAlias));
        s.update(cleartext.getBytes());
        byte[] signature = s.sign();

        return Base64.encodeToString(signature, Base64.NO_PADDING + Base64.NO_WRAP);
    }

    public Boolean verify(String keyAlias, String cleartext, String signature) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableEntryException, SignatureException, InvalidKeyException {
        KeyStore ks = loadKeyStore();

        KeyStore.Entry entry = ks.getEntry(keyAlias, null);

        byte[] signatureData = Base64.decode(signature, Base64.NO_PADDING + Base64.NO_WRAP);//Base64.decode(signature, Base64.NO_PADDING + Base64.NO_WRAP);

        Signature s = Signature.getInstance("SHA256withECDSA");

        if ((entry instanceof KeyStore.TrustedCertificateEntry)) {
            s.initVerify(((KeyStore.TrustedCertificateEntry) entry).getTrustedCertificate().getPublicKey());
        } else {
            assert entry instanceof KeyStore.PrivateKeyEntry;

            s.initVerify(((KeyStore.PrivateKeyEntry) entry).getCertificate().getPublicKey());
        }

        s.update(cleartext.getBytes());

        return s.verify(signatureData);
    }

    private EncryptedMessage encrypt(String cleartext, SecretKey encryptionKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        return encrypt(
            cleartext.getBytes(StandardCharsets.UTF_8),
            encryptionKey
        );
    }

    private EncryptedMessage encrypt(byte[] unencryptedData, SecretKey encryptionKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
        byte[] iv = cipher.getIV();
        return new EncryptedMessage(cipher.doFinal(unencryptedData), iv);
    }

    private String decrypt(EncryptedMessage encryptedMessage, SecretKey encryptionKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        return new String(
            decrypt(
                encryptedMessage.data,
                encryptedMessage.iv,
                encryptionKey
            ),
            StandardCharsets.UTF_8
        );
    }

    private byte[] decrypt(byte[] encryptedData, byte[] iv, SecretKey encryptionKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, encryptionKey, spec);
        return cipher.doFinal(encryptedData);
    }

    private SerializedEncryptedMessage serializeEncryptedMessage(EncryptedMessage encryptedMessage) {
        return new SerializedEncryptedMessage(
            Base64.encodeToString(encryptedMessage.data, Base64.NO_WRAP),
            Base64.encodeToString(encryptedMessage.iv, Base64.NO_WRAP)
        );
    }

    private EncryptedMessage deserializeEncryptedMessage(SerializedEncryptedMessage encryptedMessage) {
        return new EncryptedMessage(
            Base64.decode(encryptedMessage.ciphertext, Base64.NO_WRAP),
            Base64.decode(encryptedMessage.iv, Base64.NO_WRAP)
        );
    }

    private RecoverableKey keyToRecoverableKey(Key key, String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        String saltStr = Base64.encodeToString(salt, Base64.NO_WRAP);

        SecretKey wrappingKey = generatePasswordKey(password, saltStr);
        EncryptedMessage encryptedKey = wrapKey(key, wrappingKey);

        return new RecoverableKey(
            Base64.encodeToString(encryptedKey.data, Base64.NO_WRAP),
            Base64.encodeToString(encryptedKey.iv, Base64.NO_WRAP),
            saltStr
        );
    }

    private RecoverableKeyPair keyPairToRecoverableKeyPair(KeyPair keyPair, String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        SerializedEncryptedMessage serializedEncryptedMessage = serializeEncryptedMessage(wrapKey(keyPair.getPrivate(), generatePasswordKey(password, salt)));

        return new RecoverableKeyPair(
            new RecoverableKey(
                serializedEncryptedMessage.ciphertext,
                serializedEncryptedMessage.iv,
                Base64.encodeToString(salt, Base64.NO_WRAP)
            ),
            Base64.encodeToString(keyPair.getPublic().getEncoded(), Base64.NO_WRAP)
        );
    }

    private SecretKey loadSecretKey(String keyAlias) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableEntryException {
        return loadSecretKey(keyAlias, loadKeyStore());
    }

    private SecretKey loadSecretKey(String keyAlias, KeyStore keyStore) throws UnrecoverableEntryException, KeyStoreException, NoSuchAlgorithmException {
        KeyStore.Entry entry = keyStore.getEntry(keyAlias, null);

        assert entry instanceof KeyStore.SecretKeyEntry;

        return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
    }

    private PrivateKey loadPrivateKey(String keyAlias, KeyStore keyStore) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableEntryException {
        KeyStore.Entry entry = keyStore.getEntry(keyAlias, null);

        return ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
    }

    private KeyPair loadKeyPair(String keyAlias) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, UnrecoverableEntryException {
        return loadKeyPair(keyAlias, loadKeyStore());
    }

    private KeyPair loadKeyPair(String keyAlias, KeyStore keyStore) throws UnrecoverableEntryException, KeyStoreException, NoSuchAlgorithmException {
        KeyStore.PrivateKeyEntry entry = ((KeyStore.PrivateKeyEntry) keyStore.getEntry(keyAlias, null));

        return new KeyPair(entry.getCertificate().getPublicKey(), entry.getPrivateKey());
    }

    private PrivateKey loadPrivateKey(String keyAlias) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableEntryException {
        return loadPrivateKey(keyAlias, loadKeyStore());
    }

    private PublicKey loadPublicKey(String keyAlias, KeyStore keyStore) throws UnrecoverableEntryException, KeyStoreException, NoSuchAlgorithmException {
        KeyStore.Entry publicKeyEntry = keyStore.getEntry(keyAlias, null);
        if (publicKeyEntry instanceof KeyStore.TrustedCertificateEntry) {
            return ((KeyStore.TrustedCertificateEntry) publicKeyEntry).getTrustedCertificate().getPublicKey();
        }
        return ((KeyStore.PrivateKeyEntry) publicKeyEntry).getCertificate().getPublicKey();
    }

    private PublicKey loadPublicKey(String keyAlias) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableEntryException {
        return loadPublicKey(keyAlias, loadKeyStore());
    }

    private KeyStore loadKeyStore() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        return ks;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void importPublicKey(String alias, String publicKey, int purposes) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException, OperatorCreationException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC);
        kpg.initialize(new ECGenParameterSpec("secp521r1"));
        KeyPair keyPair = kpg.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();

        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);

        ks.setEntry(
            alias,
            new KeyStore.TrustedCertificateEntry(
                generateSelfSignedCertificate(
                    privateKey,
                    KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC).generatePublic(
                        new X509EncodedKeySpec(Base64.decode(publicKey, Base64.NO_WRAP))
                    )
                )
            ),
            new KeyProtection.Builder(purposes)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build()
        );
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void recoverKeyPair(String alias, RecoverableKeyPair recoverableKeyPair, String password, int purposes) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, OperatorCreationException {
        KeyStore ks = loadKeyStore();

        PrivateKey privateKey = unwrapPrivateKey(
            Base64.decode(recoverableKeyPair.privateKey.ciphertext, Base64.NO_WRAP),
            Base64.decode(recoverableKeyPair.privateKey.iv, Base64.NO_WRAP),
            generatePasswordKey(password, recoverableKeyPair.privateKey.salt)
        );
        KeyFactory kf = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC);

        ks.setEntry(
            alias,
            new KeyStore.PrivateKeyEntry(
                privateKey,
                new Certificate[] {
                    generateSelfSignedCertificate(
                        privateKey,
                        kf.generatePublic(
                            new X509EncodedKeySpec(Base64.decode(recoverableKeyPair.publicKey, Base64.NO_WRAP))
                        )
                    )
                }
            ),
            new KeyProtection.Builder(purposes)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build()
        );
    }

    private EncryptedMessage wrapKey(Key keyToWrap, SecretKey wrappingKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.WRAP_MODE, wrappingKey);
        byte[] iv = cipher.getIV();
        return new EncryptedMessage(cipher.wrap(keyToWrap), iv);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private Key unwrapKey(byte[] encryptedData, byte[] iv, SecretKey wrappingKey, String algorithm, int keyType) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.UNWRAP_MODE, wrappingKey, spec);
        return cipher.unwrap(encryptedData, algorithm, keyType);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private PrivateKey unwrapPrivateKey(byte[] encryptedData, byte[] iv, SecretKey wrappingKey) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        return (PrivateKey) unwrapKey(encryptedData, iv, wrappingKey, KeyProperties.KEY_ALGORITHM_EC, Cipher.PRIVATE_KEY);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private SecretKey unwrapSecretKey(byte[] encryptedData, byte[] iv, SecretKey wrappingKey) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        return (SecretKey) unwrapKey(encryptedData, iv, wrappingKey, KeyProperties.KEY_ALGORITHM_AES, Cipher.SECRET_KEY);
    }

    private byte[] deriveAgreedKey(String privateKeyAlias, String publicKeyAlias) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, UnrecoverableEntryException, InvalidKeyException {
        KeyStore ks = loadKeyStore();
        KeyPair keyPair = loadKeyPair(privateKeyAlias, ks);

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        if (!privateKeyAlias.equals(publicKeyAlias)) {
            publicKey = loadPublicKey(publicKeyAlias, ks);
        }

        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", ks.getProvider());
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);

        return keyAgreement.generateSecret();
    }

    private byte[] deriveInfoKey(byte[] secret, String info) throws IOException, GeneralSecurityException {
        byte[] salt = {};
        ByteArrayOutputStream infoStream = new ByteArrayOutputStream();
        infoStream.write(info.getBytes(StandardCharsets.UTF_8));

        return Hkdf.computeHkdf(
            "HMACSHA256",
            secret,
            salt,
            infoStream.toByteArray(),
            32
        );
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private RecoverableKeyPair generateRecoverableSignatureKeyPair(String password, byte[] salt) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, CertificateException, KeyStoreException, IOException, BadPaddingException, InvalidKeyException, OperatorCreationException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC);

        generator.initialize(new ECGenParameterSpec("secp521r1"));

        return keyPairToRecoverableKeyPair(generator.generateKeyPair(), password, salt);
    }

    @RequiresApi(api = Build.VERSION_CODES.S)
    private RecoverableKeyPair generateRecoverableAgreementKeyPair(String password, byte[] salt) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, CertificateException, KeyStoreException, IOException, BadPaddingException, InvalidKeyException, OperatorCreationException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC);

        generator.initialize(new ECGenParameterSpec("secp521r1"));

        return keyPairToRecoverableKeyPair(generator.generateKeyPair(), password, salt);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private RecoverableKey generateRecoverableKey(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, CertificateException, KeyStoreException, IOException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES);
        keyGenerator.init(256);

        return keyToRecoverableKey(keyGenerator.generateKey(), password, salt);
    }

    private X509Certificate generateSelfSignedCertificate(PrivateKey privateKey, PublicKey publicKey) throws IOException, OperatorCreationException, CertificateException {
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA512WITHPLAIN-ECDSA");//""SHA512WITHECDSA");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        AsymmetricKeyParameter keyParam = PrivateKeyFactory.createKey(privateKey.getEncoded());
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        ContentSigner signer = new BcECContentSignerBuilder(sigAlgId, digAlgId).build(keyParam);
        X500Name issuer = new X500Name("CN=Tolga Okur CA, L=Istanbul");
        X500Name subject = new X500Name("CN=MyBeautifulApp, L=Istanbul");
        BigInteger serial = BigInteger.valueOf(1); // Update with unique one if it will be used to identify this certificate
        Calendar notBefore = Calendar.getInstance();
        Calendar notAfter = Calendar.getInstance();
        notAfter.add(Calendar.YEAR, 20); // This certificate is valid for 20 years.

        X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(issuer,
                serial,
                notBefore.getTime(),
                notAfter.getTime(),
                subject,
                spki
        );
        X509CertificateHolder certificateHolder = v3CertGen.build(signer);

        return new JcaX509CertificateConverter().getCertificate(certificateHolder);
    }

    private byte[] generateSalt() {
        byte[] salt = new byte[128];

        SecureRandom secRandom = new SecureRandom();
        secRandom.nextBytes(salt);

        return salt;
    }

    private SecretKey generatePasswordKey(String password, String salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return generatePasswordKey(password, Base64.decode(salt, Base64.NO_WRAP));
    }

    private SecretKey generatePasswordKey(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(
                new PBEKeySpec(
                        password.toCharArray(),
                        salt,
                        100000,
                        32 * 8
                )
        );
    }
}
