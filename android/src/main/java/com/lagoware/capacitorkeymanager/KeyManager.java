package com.lagoware.capacitorkeymanager;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.security.keystore.StrongBoxUnavailableException;
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

    private SecretKey passwordWrappingParamsToWrappingKey(PasswordWrappingParams params) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(
            new PBEKeySpec(
                params.password.toCharArray(),
                params.salt,
                100000,
                32 * 8
            )
        );
    }

    private SecretKey resolveKeyReference(KeyReference params) throws GeneralSecurityException, IOException {
        if (params.publicKeyAlias == null) {
            return loadSecretKey(params.keyAlias);
        } else {
            byte[] sharedSecret = deriveAgreedKey(params.keyAlias, params.publicKeyAlias);

            if (params.info != null) {
                sharedSecret = deriveInfoKey(sharedSecret, params.info);
            }

            return new SecretKeySpec(sharedSecret, 0, 32, "AES/GCM/NoPadding");
        }
    }

    private SecretKey resolveEncryptionKey(EncryptionKeySpec params) throws GeneralSecurityException, IOException {
        if (params instanceof PasswordWrappingParams passwordParams) {
            return passwordWrappingParamsToWrappingKey(passwordParams);
        } else if (params instanceof KeyReference keyReference){
            return resolveKeyReference(keyReference);
        }
        throw new Error("Unrecognized encryption key spec");
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private RecoverableKeyPair generateRecoverableEcKeyPair(EncryptionKeySpec params) throws GeneralSecurityException, IOException {
        byte[] salt = params instanceof PasswordWrappingParams passwordParams
            ? passwordParams.fillSalt()
            : null;

        KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC);

        generator.initialize(new ECGenParameterSpec("secp521r1"));

        KeyPair keyPair = generator.generateKeyPair();
        SecretKey wrappingKey = resolveEncryptionKey(params);

        return new RecoverableKeyPair(
            new RecoverableKey(
                wrapKey(keyPair.getPrivate(), wrappingKey),
                salt
            ),
            keyPair.getPublic().getEncoded()
        );
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public RecoverableKey generateRecoverableKey(EncryptionKeySpec params) throws GeneralSecurityException, IOException {
        byte[] salt = params instanceof PasswordWrappingParams passwordParams
            ? passwordParams.fillSalt()
            : null;
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES);
        keyGenerator.init(256);
        SecretKey wrappingKey = resolveEncryptionKey(params);

        return new RecoverableKey(
            wrapKey(keyGenerator.generateKey(), wrappingKey),
            salt
        );
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public RecoverableKeyPair generateRecoverableSignatureKeyPair(EncryptionKeySpec params) throws GeneralSecurityException, IOException {
        return generateRecoverableEcKeyPair(params);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public RecoverableKeyPair generateRecoverableAgreementKeyPair(EncryptionKeySpec params) throws GeneralSecurityException, IOException {
        return generateRecoverableEcKeyPair(params);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public void generateKey(String keyAlias) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            try {
                KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
                keyGenerator.init(
                    new KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setIsStrongBoxBacked(true)
                        .build()
                );
                keyGenerator.generateKey();
                return;
            } catch (StrongBoxUnavailableException error) {

            }
        }
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

    public Boolean checkAliasExists(String keyAlias) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyStore ks = loadKeyStore();

        return ks.containsAlias(keyAlias);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public RecoverableKey rewrapKey(RecoverableKey recoverableKey, EncryptionKeySpec unwrapWith, EncryptionKeySpec rewrapWith) throws GeneralSecurityException, IOException {
        if (unwrapWith instanceof PasswordWrappingParams unwrapParams) {
            unwrapParams.fillSalt(recoverableKey.salt);
        }
        SecretKey unwrapKey = resolveEncryptionKey(unwrapWith);

        SecretKey unwrappedKey = unwrapSecretKey(
            Base64.decode(recoverableKey.ciphertext, Base64.NO_WRAP),
            Base64.decode(recoverableKey.iv, Base64.NO_WRAP),
            unwrapKey
        );

        byte[] salt = rewrapWith instanceof PasswordWrappingParams rewrapParams
            ? rewrapParams.fillSalt()
            : null;

        SecretKey rewrapKey = resolveEncryptionKey(rewrapWith);

        return new RecoverableKey(
            wrapKey(unwrappedKey, rewrapKey),
            salt
        );
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private RecoverableKey rewrapPrivateKey(RecoverableKey recoverableKey, EncryptionKeySpec unwrapWith, EncryptionKeySpec rewrapWith) throws GeneralSecurityException, IOException {
        if (unwrapWith instanceof PasswordWrappingParams unwrapParams) {
            unwrapParams.fillSalt(recoverableKey.salt);
        }
        SecretKey unwrapKey = resolveEncryptionKey(unwrapWith);

        PrivateKey unwrappedKey = unwrapPrivateKey(
            Base64.decode(recoverableKey.ciphertext, Base64.NO_WRAP),
            Base64.decode(recoverableKey.iv, Base64.NO_WRAP),
            unwrapKey
        );

        byte[] salt = rewrapWith instanceof PasswordWrappingParams rewrapParams
            ? rewrapParams.fillSalt()
            : null;

        SecretKey rewrapKey = resolveEncryptionKey(rewrapWith);

        return new RecoverableKey(
            wrapKey(unwrappedKey, rewrapKey),
            salt
        );
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public RecoverableKeyPair rewrapSignatureKeyPair(RecoverableKeyPair recoverableKeyPair, EncryptionKeySpec unwrapWith, EncryptionKeySpec rewrapWith) throws GeneralSecurityException, IOException {
        RecoverableKey rewrappedKey = rewrapPrivateKey(recoverableKeyPair.privateKey, unwrapWith, rewrapWith);

        return new RecoverableKeyPair(
            rewrappedKey,
            recoverableKeyPair.publicKey
        );
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public RecoverableKeyPair rewrapAgreementKeyPair(RecoverableKeyPair recoverableKeyPair, EncryptionKeySpec unwrapWith, EncryptionKeySpec rewrapWith) throws GeneralSecurityException, IOException {
        RecoverableKey rewrappedKey = rewrapPrivateKey(recoverableKeyPair.privateKey, unwrapWith, rewrapWith);

        return new RecoverableKeyPair(
            rewrappedKey,
            recoverableKeyPair.publicKey
        );
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void recoverKeyPair(String alias, RecoverableKeyPair recoverableKeyPair, EncryptionKeySpec spec, int purposes) throws GeneralSecurityException, IOException, OperatorCreationException {
        KeyStore ks = loadKeyStore();

        if (spec instanceof PasswordWrappingParams passwordParams) {
            passwordParams.fillSalt(recoverableKeyPair.privateKey.salt);
        }

        SecretKey encryptionKey = resolveEncryptionKey(spec);

        PrivateKey privateKey = unwrapPrivateKey(
            Base64.decode(recoverableKeyPair.privateKey.ciphertext, Base64.NO_WRAP),
            Base64.decode(recoverableKeyPair.privateKey.iv, Base64.NO_WRAP),
            encryptionKey
        );

        KeyFactory kf = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC);

        KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(
            privateKey,
            new Certificate[] {
                generateSelfSignedCertificate(
                    privateKey,
                    kf.generatePublic(
                        new X509EncodedKeySpec(Base64.decode(recoverableKeyPair.publicKey, Base64.NO_WRAP))
                    )
                )
            }
        );

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            try {
                ks.setEntry(
                    alias,
                    privateKeyEntry,
                    new KeyProtection.Builder(purposes)
                        .setIsStrongBoxBacked(true)
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .build()
                );
                return;
            } catch (KeyStoreException | StrongBoxUnavailableException error) {

            }
        }

        ks.setEntry(
            alias,
            privateKeyEntry,
            new KeyProtection.Builder(purposes)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build()
        );
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public void recoverSignatureKeyPair(String alias, RecoverableKeyPair recoverableKeyPair, EncryptionKeySpec spec) throws GeneralSecurityException, IOException, OperatorCreationException {
        recoverKeyPair(alias, recoverableKeyPair, spec, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY);
    }

    @RequiresApi(api = Build.VERSION_CODES.S)
    public void recoverAgreementKeyPair(String alias, RecoverableKeyPair recoverableKeyPair, EncryptionKeySpec spec) throws GeneralSecurityException, IOException, OperatorCreationException {
        recoverKeyPair(alias, recoverableKeyPair, spec, KeyProperties.PURPOSE_AGREE_KEY);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public void recoverKey(String alias, RecoverableKey recoverableKey, EncryptionKeySpec spec) throws GeneralSecurityException, IOException {
        KeyStore ks = loadKeyStore();

        if (spec instanceof PasswordWrappingParams passwordParams) {
            passwordParams.fillSalt(recoverableKey.salt);
        }
        SecretKey encryptionKey = resolveEncryptionKey(spec);
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(
            unwrapSecretKey(
                Base64.decode(recoverableKey.ciphertext, Base64.NO_WRAP),
                Base64.decode(recoverableKey.iv, Base64.NO_WRAP),
                encryptionKey
            )
        );

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            try {
                ks.setEntry(
                    alias,
                    secretKeyEntry,
                    new KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setIsStrongBoxBacked(true)
                        .build()
                );
                return;
            } catch (KeyStoreException | StrongBoxUnavailableException error) {

            }
        }

        ks.setEntry(
            alias,
            secretKeyEntry,
            new KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build()
        );
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public void importPublicSignatureKey(String alias, String publicKey) throws InvalidAlgorithmParameterException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, OperatorCreationException, NoSuchProviderException {
        importPublicKey(alias, publicKey, KeyProperties.PURPOSE_VERIFY);
    }

    @RequiresApi(api = Build.VERSION_CODES.S)
    public void importPublicAgreementKey(String alias, String publicKey) throws InvalidAlgorithmParameterException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, OperatorCreationException, NoSuchProviderException {
        importPublicKey(alias, publicKey, KeyProperties.PURPOSE_AGREE_KEY);
    }

    public SerializedEncryptedMessage encrypt(EncryptionKeySpec spec, String cleartext) throws GeneralSecurityException, IOException {
        if (spec instanceof PasswordWrappingParams passwordParams) {
            passwordParams.fillSalt();
        }
        SecretKey encryptionKey = resolveEncryptionKey(spec);

        return encrypt(
            cleartext,
            encryptionKey
        ).serialize();
    }

    public String decrypt(EncryptionKeySpec spec, SerializedEncryptedMessage message) throws GeneralSecurityException, IOException {
        if (spec instanceof PasswordWrappingParams passwordParams) {
            passwordParams.fillSalt();
        }

        SecretKey encryptionKey = resolveEncryptionKey(spec);

        return decrypt(
            message.deserialize(),
            encryptionKey
        );
    }

    private EncryptedMessage encrypt(String cleartext, SecretKey encryptionKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        return encrypt(
            cleartext.getBytes(StandardCharsets.UTF_8),
            encryptionKey
        );
    }

    private EncryptedMessage encrypt(byte[] unencryptedData, SecretKey encryptionKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
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

    public String sign(String keyAlias, String cleartext) throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException, CertificateException, IOException, InvalidKeyException, SignatureException, NoSuchProviderException {
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(loadPrivateKey(keyAlias));
        s.update(cleartext.getBytes());
        byte[] signature = s.sign();

        return Base64.encodeToString(signature, Base64.NO_PADDING + Base64.NO_WRAP);
    }

    public Boolean verify(String keyAlias, String cleartext, String signature) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableEntryException, SignatureException, InvalidKeyException, NoSuchProviderException, ClassCastException {
        KeyStore ks = loadKeyStore();

        KeyStore.Entry entry = ks.getEntry(keyAlias, null);

        byte[] signatureData = Base64.decode(signature, Base64.NO_PADDING + Base64.NO_WRAP);

        Signature s = Signature.getInstance("SHA256withECDSA");

        if ((entry instanceof KeyStore.TrustedCertificateEntry)) {
            s.initVerify(((KeyStore.TrustedCertificateEntry) entry).getTrustedCertificate().getPublicKey());
        } else {
            s.initVerify(((KeyStore.PrivateKeyEntry) entry).getCertificate().getPublicKey());
        }

        s.update(cleartext.getBytes());

        return s.verify(signatureData);
    }

    private SecretKey loadSecretKey(String keyAlias) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, UnrecoverableEntryException {
        return loadSecretKey(keyAlias, loadKeyStore());
    }

    private SecretKey loadSecretKey(String keyAlias, KeyStore keyStore) throws UnrecoverableEntryException, KeyStoreException, NoSuchAlgorithmException {
        KeyStore.Entry entry = keyStore.getEntry(keyAlias, null);

        return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
    }

    private PrivateKey loadPrivateKey(String keyAlias, KeyStore keyStore) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException {
        KeyStore.Entry entry = keyStore.getEntry(keyAlias, null);

        return ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
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

        KeyStore ks = loadKeyStore();
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

    private EncryptedMessage wrapKey(Key keyToWrap, SecretKey wrappingKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.WRAP_MODE, wrappingKey);
        byte[] iv = cipher.getIV();
        return new EncryptedMessage(cipher.wrap(keyToWrap), iv);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private Key unwrapKey(byte[] encryptedData, byte[] iv, SecretKey wrappingKey, String algorithm, int keyType) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.UNWRAP_MODE, wrappingKey, spec);
        return cipher.unwrap(encryptedData, algorithm, keyType);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private PrivateKey unwrapPrivateKey(byte[] encryptedData, byte[] iv, SecretKey wrappingKey) throws InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        return (PrivateKey) unwrapKey(encryptedData, iv, wrappingKey, KeyProperties.KEY_ALGORITHM_EC, Cipher.PRIVATE_KEY);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private SecretKey unwrapSecretKey(byte[] encryptedData, byte[] iv, SecretKey wrappingKey) throws InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
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

    X509Certificate generateSelfSignedCertificate(PrivateKey privateKey, PublicKey publicKey) throws IOException, OperatorCreationException, CertificateException {
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
}
