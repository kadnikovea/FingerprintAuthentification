package com.kadnikovea.fingerauth;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class MainActivity extends AppCompatActivity {

    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    private static Cipher cipher;
    private KeyStore keyStore;
    private KeyGenerator keyGenerator;

    byte[] encryptionIv;
    byte[] encription;

    EditText editText;
    TextView tvEnc;
    TextView tvDec;

    Button bnEnc;
    Button bnDec;


    private static final String KEY_NAME = "myVerySecretKey";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        editText = findViewById(R.id.et);

        tvEnc = findViewById(R.id.tvEncrypted);
        tvDec = findViewById(R.id.tvDecrypted);

        bnEnc =findViewById(R.id.btnEncrypt);
        bnDec = findViewById(R.id.btnDecrypt);


        bnEnc.setOnClickListener(v ->{

            String textToEncript =  editText.getText().toString().trim();

            if(textToEncript != null && !textToEncript.isEmpty())
                encrypt(textToEncript);
            else
                Toast.makeText(this, "Input is empty", Toast.LENGTH_LONG).show();

        });

        bnDec.setOnClickListener(v ->{

            decript(encription, encryptionIv);

        });

        bnEnc.setEnabled(false);
        bnDec.setEnabled(false);

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
            //do work
            initVerification();


        }else {
            //api lower 23
            Toast.makeText(this, "Android Version is too old for FingeprintApi", Toast.LENGTH_LONG).show();

            bnEnc.setEnabled(false);
            bnDec.setEnabled(false);

        }
        }

    private void encrypt(String textToEncript) {

        try {

            final SecretKey secretKey = (SecretKey) keyStore.getKey(KEY_NAME, null);

            cipher = Cipher.getInstance(TRANSFORMATION);

            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            encryptionIv = cipher.getIV();


            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {

                HardwareFingerScannerHandler.create(this, cipher, () -> {
                    try {

                        encription = cipher.doFinal(textToEncript.getBytes("UTF-8"));
                        tvEnc.setText(new String(encription));
                        bnDec.setEnabled(true);

                    } catch (BadPaddingException e) {
                        e.printStackTrace();
                    } catch (IllegalBlockSizeException e) {
                        e.printStackTrace();
                    } catch (UnsupportedEncodingException e) {
                        e.printStackTrace();
                    }

                });


            }

        }  catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }  catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }

    private void decript(byte[] encription, byte[] encryptionIv) {

        try {

            keyStore.load(null);

            final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore
                    .getEntry(KEY_NAME, null);

            final SecretKey secretKey = secretKeyEntry.getSecretKey();

            cipher = Cipher.getInstance(TRANSFORMATION);
            final GCMParameterSpec spec = new GCMParameterSpec(128, encryptionIv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);



            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {

                HardwareFingerScannerHandler.create(this, cipher, () ->{
                    try {
                        final byte[] decodeData = cipher.doFinal(encription);
                        final String decryptedString = new String(decodeData, "UTF-8");
                        tvDec.setText(decryptedString);

                    } catch (BadPaddingException e) {
                        e.printStackTrace();
                    } catch (IllegalBlockSizeException e) {
                        e.printStackTrace();
                    } catch (UnsupportedEncodingException e) {
                        e.printStackTrace();
                    }
                });

            }

        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

    }


    @RequiresApi(api = Build.VERSION_CODES.M)
    private boolean isKeyReady() {
        try {
            return keyStore.containsAlias(KEY_NAME) || generateNewKey();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        Toast.makeText(this, "isKey", Toast.LENGTH_LONG).show();

        return false;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private boolean generateNewKey() {

        try {
            keyGenerator = KeyGenerator
                    .getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
            final KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(KEY_NAME,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build();

            keyGenerator.init(keyGenParameterSpec);

            keyGenerator.generateKey();

            return true;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        Toast.makeText(this, "KeyGen", Toast.LENGTH_LONG).show();

        return false;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void initVerification() {


        if(getKeyStore() && getCipher() && isKeyReady()){
                bnEnc.setEnabled(true);
         }else {
             Toast.makeText(this, "!!!!!!!!!!!!!!!!", Toast.LENGTH_LONG).show();

        }
    }

    private boolean getKeyStore() {
        try {
            keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
            return true;
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    private boolean getCipher() {

        try {
            cipher = Cipher.getInstance(TRANSFORMATION);
            return true;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        Toast.makeText(this, "Cipher", Toast.LENGTH_LONG).show();

        return false;

    }



//
//    @RequiresApi(Build.VERSION_CODES.M)
//    public void generateKeyPair(){
//
//            try {
//
//            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
//                keyPairGenerator.initialize(
//                        new KeyGenParameterSpec.Builder(KEY_NAME,
//                                KeyProperties.PURPOSE_SIGN)
//                                .setDigests(KeyProperties.DIGEST_SHA256)
//                                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
//                                .setUserAuthenticationRequired(true)
//                                .build());
//            keyPairGenerator.generateKeyPair();
//
//
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        } catch (NoSuchProviderException e) {
//            e.printStackTrace();
//        } catch (InvalidAlgorithmParameterException e) {
//            e.printStackTrace();
//        }
//
//
//
//    }
//
//    public void getPublicPrivateKey(){
//
//
//        KeyStore keyStore = null;
//        try {
//            keyStore = KeyStore.getInstance("AndroidKeyStore");
//            keyStore.load(null);
//            PublicKey publicKey =
//                    keyStore.getCertificate(MainActivity.KEY_NAME).getPublicKey();
//
//            keyStore = KeyStore.getInstance("AndroidKeyStore");
//            keyStore.load(null);
//            PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_NAME, null);
//
//        } catch (KeyStoreException e) {
//            e.printStackTrace();
//        } catch (CertificateException e) {
//            e.printStackTrace();
//        } catch (UnrecoverableKeyException e) {
//            e.printStackTrace();
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//
//
//    }
//
//
//    @RequiresApi(Build.VERSION_CODES.M)
//    private void startListening(){
//
//        try {
//            Signature signature = Signature.getInstance("SHA256withECDSA");
//            keyStore = KeyStore.getInstance("AndroidKeyStore");
//
//            keyStore.load(null);
//            PrivateKey key = (PrivateKey) keyStore.getKey(KEY_NAME, null);
//            signature.initSign(key);
//            FingerprintManager.CryptoObject cryptObject = new FingerprintManager.CryptoObject(signature);
//
//            CancellationSignal cancellationSignal = new CancellationSignal();
//            FingerprintManager fingerprintManager =
//                    null;
//                fingerprintManager = this.getSystemService(FingerprintManager.class);
//            fingerprintManager.authenticate(cryptoObject, cancellationSignal, 0, this, null);
//
//
//
//        } catch (KeyStoreException e) {
//            e.printStackTrace();
//        } catch (CertificateException e) {
//            e.printStackTrace();
//        } catch (UnrecoverableKeyException e) {
//            e.printStackTrace();
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        } catch (IOException e) {
//            e.printStackTrace();
//        } catch (InvalidKeyException e) {
//            e.printStackTrace();
//        }
//
//
//
//    }
//
//    private static boolean getCipher() {
//        try {
//            sCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
//            return true;
//        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
//            e.printStackTrace();
//        }
//        return false;
//    }
//
//
//    @TargetApi(Build.VERSION_CODES.M)
//    private boolean initCipher(int mode) {
//        try {
//            keyStore.load(null);
//            switch (mode) {
//                case Cipher.ENCRYPT_MODE:
//                    initEncodeCipher(mode);
//                    break;
//                case Cipher.DECRYPT_MODE:
//                    initDecodeCipher(mode);
//                    break;
//                default:
//                    return false; //this cipher is only for encode\decode
//            }
//            return true;
//        } catch (KeyPermanentlyInvalidatedException exception) {
//            deleteInvalidKey();
//        } catch (KeyStoreException | CertificateException | UnrecoverableKeyException | IOException |
//                NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException | InvalidAlgorithmParameterException e) {
//            e.printStackTrace();
//        }
//        return false;
//    }
//
//    private void initDecodeCipher(int mode) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException {
//        PrivateKey key = (PrivateKey) keyStore.getKey(KEY_NAME, null);
//        sCipher.init(mode, key);
//    }
//
//    private void initEncodeCipher(int mode) throws KeyStoreException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
//        PublicKey key = keyStore.getCertificate(KEY_NAME).getPublicKey();
//        PublicKey unrestricted = KeyFactory.getInstance(key.getAlgorithm()).generatePublic(new X509EncodedKeySpec(key.getEncoded()));
//        OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
//        sCipher.init(mode, unrestricted, spec);
//    }
//
//
//    public void deleteInvalidKey() {
//        if (getKeyStore()) {
//            try {
//                keyStore.deleteEntry(KEY_NAME);
//            } catch (KeyStoreException e) {
//                e.printStackTrace();
//            }
//        }
//    }
//
//
//    private boolean getKeyStore() {
//
//        try {
//            keyStore = KeyStore.getInstance("AndroidKeyStore");
//            keyStore.load(null);
//            return true;
//        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
//            e.printStackTrace();
//        }
//
//        return false;
//
//    }




}
