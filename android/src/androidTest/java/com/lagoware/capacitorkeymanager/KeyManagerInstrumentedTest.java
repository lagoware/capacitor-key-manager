package com.lagoware.capacitorkeymanager;

import static org.junit.Assert.*;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.util.Base64;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class KeyManagerInstrumentedTest {

    private final RecoverableKeyPair testRecoverableSigKeyPair = new RecoverableKeyPair(
        new RecoverableKey(
            "CrILhGlCg/XEN3LDk0/qsOatMJ/W3QMX5ATVTm7bcM9DAHFacMZRCEZq8yfS7WIucHaZ7mGJBZJcBASOy/p3Ue1FqQWgFPWUvffGIFTBsJHz6PA2b0A9a0jCMJ6kdqmkajqeO7FygxOHDf3Y3Uf9dZ5bW3yWlW9dO0rAreF54LxNPi6tZrpDGLxiWzW90tjEn/hhpw6CDHAw10LKXuMTykXQ5Ly9QBH4edYuVTedMX0y0FC/26KyQSQISbNSjdrGvVcMjjXT3e9FhSrk6vfCw28jlKZi5hDyouKnpHeMcUyqZCt29K/89qO+eQZYZ240oYzKnLosEuo8aJSmFvlcWyo=",
            "XqFZwuzIw8yc6MQl",
            "UfyXAyYhOPG2fVZac4pxb9DVphcaGa/5ynX2/LP3OsAJFn+UQAq+tZBfvEaXhnucQT+ZORXY71XYKQolrbkEaLDtQRMf6c6APe6ZGhQWCDmRsiFaYAGdwPH0jfCj4l/rx2ZRTPKNrUMaMegn4BqPMM25nlgDmtr5/k5Ds5bIgno="
        ),
        "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBmRohtYjM4R120jr8cjTouYJ68qXssr+KUnxkcQ+eRei/ES+bZ2D3WLiVa2M0nItSFmCx0bitMlsKSczIPV2DkqoAKNditdQNIYgajNBmHcMhPykvMh+2qdshUIJekr6M1GSgXtiBmfT0ffHMgItBGbWJw4HiYIlZKXFRdJ3fVSyVOvs="
    );

    private final RecoverableKeyPair testRecoverableAgreeKeyPair = new RecoverableKeyPair(
        new RecoverableKey(
            "1qgbz6J49/4FS2a+MS7Rbleb7+aK5hMTOKXX2a7EGRLI4Plef98AA82yqcQg2WsDiR277IntIC4GIUrJ3A5wNgqrOTVwsCJtfI/CX/y2d1/dFllQgzIG92leBls6E4XQKWDYf3roPiIE4YUY3Uokx5HpiP8z6N9beMlIOWM1M5KJTm8qyTflPHdyBepBmfiBf2sWALuXFR9YIbZ3WCbDrS/PgEKrBZFOKVca2lu/Pgi5tQqcgccBMStpv/Y6tPJtYT/72H+XqZMeUUfr05Ax7ddnKaPX9ocysacS9KtpffosWwgLnHJrYl03eXWt/hvm5mg5syJLSWK3xOhFePOI2SQ=",
            "driVYKcAg1wzQBT9",
            "D/qvJfEShcnyEgrPuoTvY2wRM8WJs9X6JOQHJleo+n1COZHd9pnOoL5dbrkCmvUo/FsCYGnDOWBOedN2o4GEHq+8+BieY2wGSTs/Dk+De/X35kcngeDhsM/eB9s1c4kX0qDzEpzxgRUOGQsalRKjBB+U2mT3yIGvIGNYAsjKsBY="
        ),
        "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAJ0fRvGVuqr6gRytCjcwpSFfrPSd/gWDYq9gdr9lch1irR1wVN4s/b4DKkZ8lbnszoHy3XR3OajW+yx8XBgU2G/sB8T45Da45pHX4yVTyzTolN9lKNk6lLSQ5EI2vu4JVY5VZ/+BBHGagNjRn3W4cWW/I/RtbAj8F9kuhFhqxc1amQRw="
    );

    private final RecoverableKey testRecoverableKey = new RecoverableKey(
        "9XF2Ly8+uo1ng+x/XBIUZlIOwSoMYCahQf0CNMDQRQgaZVhFvr4VKpHWP+/bVEJw",
        "0kJLQny/GYm6itCZ",
        "x7/vx7ikOd122eMF7g0RbdwGKlZKyHDpJHJiJ58BBTH+w0Hys+o/zRw2KagXIr8oablCUAO0OqlLeTxjrn9ZwXKk9bNZ7O+1LUHHY0H8hYo/ouR3DUuxPh1dLlsvBLbww0V/7JKbt0zKwmnUhaxsQRfbWlzlqrcRm9+tbei7tms="
    );

    @Test
    public void generateRecoverableSignatureKeyPair() throws Exception {
        KeyManager keyManager = new KeyManager();

        RecoverableKeyPair recoverableKeyPair = keyManager.generateRecoverableSignatureKeyPair(new PasswordWrappingParams("MyPassword", null));

        assertFalse(recoverableKeyPair.publicKey.contains("\n"));
        assertEquals(212, recoverableKeyPair.publicKey.length());
        assertEquals(16, recoverableKeyPair.privateKey.iv.length());
        assertEquals(344, recoverableKeyPair.privateKey.ciphertext.length());
        assertEquals(172, recoverableKeyPair.privateKey.salt.length());

        keyManager.recoverSignatureKeyPair("MyTestKey", recoverableKeyPair, new PasswordWrappingParams("MyPassword"));

        String sig = keyManager.sign("MyTestKey", "TestValue");

        assertTrue(keyManager.verify("MyTestKey", "TestValue", sig));
        assertFalse(keyManager.verify("MyTestKey", "TestValueWrong", sig));
    }

    @Test
    public void recoverSignatureKeyPair() throws Exception {
        KeyManager keyManager = new KeyManager();
        keyManager.recoverSignatureKeyPair("DonkeyMan", testRecoverableSigKeyPair, new PasswordWrappingParams("Scrammi"));

        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry("DonkeyMan", null);

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;

        PrivateKey key = privateKeyEntry.getPrivateKey();

        KeyFactory factory = KeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore");
        KeyInfo keyInfo;
        keyInfo = factory.getKeySpec(key, KeyInfo.class);

        int securityLevel = keyInfo.getSecurityLevel();

        assertTrue(
            securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
            || securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
        );
    }

    @Test
    public void recoverAgreementKeyPair() throws Exception {
        KeyManager keyManager = new KeyManager();
        keyManager.recoverAgreementKeyPair("DonkeyMan", testRecoverableAgreeKeyPair, new PasswordWrappingParams("Scrammi"));

        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry("DonkeyMan", null);

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;

        PrivateKey key = privateKeyEntry.getPrivateKey();

        KeyFactory factory = KeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore");
        KeyInfo keyInfo;
        keyInfo = factory.getKeySpec(key, KeyInfo.class);

        int securityLevel = keyInfo.getSecurityLevel();

        assertEquals(securityLevel, KeyProperties.SECURITY_LEVEL_SOFTWARE);
//        assertTrue(
//            securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
//            || securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
//        );
    }

    @Test
    public void recoverKey() throws Exception {
        KeyManager keyManager = new KeyManager();
        keyManager.recoverKey("DonkeyMan", testRecoverableKey, new PasswordWrappingParams("Scrammi"));
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry("DonkeyMan", null);

        KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) entry;

        SecretKey key = secretKeyEntry.getSecretKey();

        SecretKeyFactory factory = SecretKeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore");
        KeyInfo keyInfo = (KeyInfo) factory.getKeySpec(key, KeyInfo.class);

        int securityLevel = keyInfo.getSecurityLevel();

        assertTrue(
            securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
            || securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
        );
    }

    @Test
    public void importPublicSignatureKey() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, CertificateException, KeyStoreException, IOException, InvalidKeySpecException, OperatorCreationException, InvalidKeyException, SignatureException, UnrecoverableEntryException, NoSuchProviderException {
        KeyManager keyManager = new KeyManager();
        KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC);
        generator.initialize(new ECGenParameterSpec("secp521r1"));
        KeyPair keyPair = generator.generateKeyPair();

        String message = "HeyEverybody";

        keyManager.importPublicSignatureKey("OtherPartyKey", Base64.encodeToString(keyPair.getPublic().getEncoded(), Base64.NO_WRAP));

        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(keyPair.getPrivate());
        s.update(message.getBytes());
        String signature = Base64.encodeToString(s.sign(), Base64.NO_PADDING + Base64.NO_WRAP);

        assertTrue(keyManager.verify("OtherPartyKey", message, signature));
        assertFalse(keyManager.verify("OtherPartyKey", "HeyEverybodyWrong", signature));
    }

    @Test
    public void generateRecoverableAgreementKeyPair() throws Exception {
        KeyManager keyManager = new KeyManager();
        RecoverableKeyPair recoverableKeyPair = keyManager.generateRecoverableAgreementKeyPair(new PasswordWrappingParams("MyPassword"));

        assertEquals(212, recoverableKeyPair.publicKey.length());
        assertEquals(16, recoverableKeyPair.privateKey.iv.length());
        assertEquals(344, recoverableKeyPair.privateKey.ciphertext.length());
        assertEquals(172, recoverableKeyPair.privateKey.salt.length());

        keyManager.recoverAgreementKeyPair("MyTestKey", recoverableKeyPair, new PasswordWrappingParams("MyPassword"));

        KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC);
        generator.initialize(new ECGenParameterSpec("secp521r1"));
        KeyPair keyPair = generator.generateKeyPair();

        keyManager.importPublicAgreementKey("OtherPartyKey", Base64.encodeToString(keyPair.getPublic().getEncoded(), Base64.NO_WRAP));

        String testString = "Meatballs";

        assertEquals(
            keyManager.decrypt(
                new KeyReference("MyTestKey", "OtherPartyKey"),
                keyManager.encrypt(new KeyReference("MyTestKey", "OtherPartyKey"), testString)
            ),
            testString
        );
        assertEquals(
            keyManager.decrypt(
                new KeyReference("MyTestKey", "MyTestKey"),
                keyManager.encrypt(new KeyReference("MyTestKey", "MyTestKey"), testString)
            ),
            testString
        );
        assertEquals(
            keyManager.decrypt(
                new KeyReference("MyTestKey", "OtherPartyKey", "Me and You"),
                keyManager.encrypt(new KeyReference("MyTestKey", "OtherPartyKey", "Me and You"), testString)
            ),
            testString
        );
        assertEquals(
            keyManager.decrypt(
                new KeyReference("MyTestKey", "MyTestKey", "Me and You"),
                keyManager.encrypt(new KeyReference("MyTestKey", "MyTestKey", "Me and You"), testString)
            ),
            testString
        );
    }

    @Test
    public void generateRecoverableKey() throws Exception {
        KeyManager keyManager = new KeyManager();

        RecoverableKey recoverableKey = keyManager.generateRecoverableKey(new PasswordWrappingParams("MyPassword"));

        assertEquals(64, recoverableKey.ciphertext.length());
        assertEquals(16, recoverableKey.iv.length());
        assertEquals(172, recoverableKey.salt.length());

        keyManager.recoverKey("MyKey", recoverableKey, new PasswordWrappingParams("MyPassword"));

        SerializedEncryptedMessage encryptedMessage = keyManager.encrypt(new KeyReference("MyKey"), "MyMessage");
        assertEquals(36, encryptedMessage.ciphertext.length());
        assertEquals(16, encryptedMessage.iv.length());

        assertEquals(keyManager.decrypt(new KeyReference("MyKey"), encryptedMessage), "MyMessage");
    }

    @Test
    public void rewrapSignatureKeyPair() throws Exception {
        KeyManager keyManager = new KeyManager();

        RecoverableKeyPair recoverableKeyPair = keyManager.rewrapSignatureKeyPair(testRecoverableSigKeyPair, new PasswordWrappingParams("Scrammi"), new PasswordWrappingParams("Whammy"));

        keyManager.recoverSignatureKeyPair("MyKey", recoverableKeyPair, new PasswordWrappingParams("Whammy"));
    }

    @Test
    public void rewrapAgreementKeyPair() throws Exception {
        KeyManager keyManager = new KeyManager();

        RecoverableKeyPair recoverableKeyPair = keyManager.rewrapAgreementKeyPair(testRecoverableAgreeKeyPair, new PasswordWrappingParams("Scrammi"), new PasswordWrappingParams("Whammy"));

        keyManager.recoverAgreementKeyPair("MyKey", recoverableKeyPair, new PasswordWrappingParams("Whammy"));
    }

    @Test
    public void rewrapKey() throws Exception {
        KeyManager keyManager = new KeyManager();

        RecoverableKey recoverableKey = keyManager.rewrapKey(testRecoverableKey, new PasswordWrappingParams("Scrammi"), new PasswordWrappingParams("Whammy"));

        keyManager.recoverKey("MyKey", recoverableKey, new PasswordWrappingParams("Whammy"));
    }

    @Test
    public void generateKey() throws Exception {
        KeyManager keyManager = new KeyManager();
        keyManager.generateKey("Danis");

        SerializedEncryptedMessage encryptedMessage = keyManager.encrypt(new KeyReference("Danis"), "MyMessage");
        assertEquals(36, encryptedMessage.ciphertext.length());
        assertEquals(16, encryptedMessage.iv.length());

        assertEquals("MyMessage", keyManager.decrypt(new KeyReference("Danis"), encryptedMessage));

        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry("Danis", null);

        KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) entry;

        SecretKey key = secretKeyEntry.getSecretKey();

        SecretKeyFactory factory = SecretKeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore");
        KeyInfo keyInfo = (KeyInfo) factory.getKeySpec(key, KeyInfo.class);

        int securityLevel = keyInfo.getSecurityLevel();

        assertTrue(
            securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
            || securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
        );
    }

    @Test
    public void generateKeyFromAgreementKey() throws GeneralSecurityException, IOException, OperatorCreationException {
        KeyManager keyManager = new KeyManager();
        RecoverableKeyPair recoverableKeyPair = keyManager.generateRecoverableAgreementKeyPair(new PasswordWrappingParams("MyPassword", null));
        keyManager.recoverAgreementKeyPair("MyTestKey", recoverableKeyPair, new PasswordWrappingParams("MyPassword"));

        KeyReference wrappingKeyRef = new KeyReference(
            "MyTestKey",
            "MyTestKey",
            "drinker"
        );
        RecoverableKey recoverableKey = keyManager.generateRecoverableKey(
            wrappingKeyRef
        );

        assertEquals(64, recoverableKey.ciphertext.length());
        assertEquals(16, recoverableKey.iv.length());

        keyManager.recoverKey("MyNewKey", recoverableKey, wrappingKeyRef);

        SerializedEncryptedMessage encryptedMessage = keyManager.encrypt(new KeyReference("MyNewKey"), "Meatballs");

        assertEquals("Meatballs", keyManager.decrypt(new KeyReference("MyNewKey"), encryptedMessage));
    }

//    @Test
//    public void ecKeyAndroid12() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, KeyStoreException, CertificateException, IOException, OperatorCreationException, UnrecoverableEntryException {
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
//                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
//        keyPairGenerator.initialize(
//                new KeyGenParameterSpec.Builder(
//                        "eckeypair",
////                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
////                        KeyProperties.PURPOSE_ATTEST_KEY
//                        KeyProperties.PURPOSE_AGREE_KEY
//                )
//                        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp521r1"))
//                        .build());
//        KeyPair myKeyPair = keyPairGenerator.generateKeyPair();
//
//        // Exchange public keys with server. A new ephemeral key MUST be used for every message.
////        PublicKey serverEphemeralPublicKey; // Ephemeral key received from server.
//
//        // Create a shared secret based on our private key and the other party's public key.
//        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "AndroidKeyStore");
//        keyAgreement.init(myKeyPair.getPrivate());
//        keyAgreement.doPhase(myKeyPair.getPublic(), true);
//        byte[] sharedSecret = keyAgreement.generateSecret();
//
//        assertEquals(sharedSecret.length, 66);
//
//    }

}
