/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

package com.example.android.fingerprintdialog;

import android.Manifest;
import android.app.Activity;
import android.app.KeyguardManager;
import android.app.Notification;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Calendar;
import java.util.GregorianCalendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.inject.Inject;
import javax.security.auth.x500.X500Principal;

/**
 * Main entry point for the sample, showing a backpack and "Purchase" button.
 */
public class MainActivity extends Activity {

    private static final String TAG = MainActivity.class.getSimpleName();

    private static final String DIALOG_FRAGMENT_TAG = "myFragment";
    private static final String SECRET_MESSAGE = "Very secret message";
    /**
     * Alias for our key in the Android Key Store
     */
    private static final String KEY_NAME = "my_key";

    private static final int FINGERPRINT_PERMISSION_REQUEST_CODE = 0;

//    private KeyPair pair = null;

    @Inject
    KeyguardManager mKeyguardManager;
    @Inject
    FingerprintAuthenticationDialogFragment mFragment;
    @Inject
    KeyStore mKeyStore;
    @Inject
    KeyPairGenerator mKeyGenerator;
    @Inject
    Signature mSignature;
    @Inject
    SharedPreferences mSharedPreferences;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ((InjectedApplication) getApplication()).inject(this);

        requestPermissions(new String[]{Manifest.permission.USE_FINGERPRINT},
                FINGERPRINT_PERMISSION_REQUEST_CODE);
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] state) {
        if (requestCode == FINGERPRINT_PERMISSION_REQUEST_CODE
                && state[0] == PackageManager.PERMISSION_GRANTED) {
            setContentView(R.layout.activity_main);
            Button purchaseButton = (Button) findViewById(R.id.purchase_button);
            if (!mKeyguardManager.isKeyguardSecure()) {
                // Show a message that the user hasn't set up a fingerprint or lock screen.
                Toast.makeText(this,
                        "Secure lock screen hasn't set up.\n"
                                + "Go to 'Settings -> Security -> Fingerprint' to set up a fingerprint",
                        Toast.LENGTH_LONG).show();
                purchaseButton.setEnabled(false);
            }
            if (!createKey()) {
                purchaseButton.setEnabled(false);
                return;
            }
            purchaseButton.setEnabled(true);
            purchaseButton.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    findViewById(R.id.confirmation_message).setVisibility(View.GONE);
                    findViewById(R.id.encrypted_message).setVisibility(View.GONE);

                    // Set up the crypto object for later. The object will be authenticated by use
                    // of the fingerprint.
                    if (initCipher()) {

                        // Show the fingerprint dialog. The user has the option to use the fingerprint with
                        // crypto, or you can fall back to using a server-side verified password.
                        mFragment.setCryptoObject(new FingerprintManager.CryptoObject(mSignature));
                        boolean useFingerprintPreference = mSharedPreferences
                                .getBoolean(getString(R.string.use_fingerprint_to_authenticate_key),
                                        true);
                        if (useFingerprintPreference) {
                            mFragment.setStage(
                                    FingerprintAuthenticationDialogFragment.Stage.FINGERPRINT);
                        } else {
                            mFragment.setStage(
                                    FingerprintAuthenticationDialogFragment.Stage.PASSWORD);
                        }
                        mFragment.show(getFragmentManager(), DIALOG_FRAGMENT_TAG);
//                        tryEncrypt();
                    } else {
                        // This happens if the lock screen has been disabled or or a fingerprint got
                        // enrolled. Thus show the dialog to authenticate with their password first
                        // and ask the user if they want to authenticate with fingerprints in the
                        // future
                        mFragment.setCryptoObject(new FingerprintManager.CryptoObject(mSignature));
                        mFragment.setStage(
                                FingerprintAuthenticationDialogFragment.Stage.NEW_FINGERPRINT_ENROLLED);
                        mFragment.show(getFragmentManager(), DIALOG_FRAGMENT_TAG);
                    }
                }
            });
        }
    }

    /**
     * Initialize the {@link Cipher} instance with the created key in the {@link #createKey()}
     * method.
     *
     * @return {@code true} if initialization is successful, {@code false} if the lock screen has
     * been disabled or reset after the key was generated, or if a fingerprint got enrolled after
     * the key was generated.
     */
    private boolean initCipher() {
        try {
            mKeyStore.load(null);
            PrivateKey key = ((KeyStore.PrivateKeyEntry)(mKeyStore.getEntry(KEY_NAME, null))).getPrivateKey();
//            mSignature.update(SECRET_MESSAGE.getBytes());
            mSignature.initSign(key);
//            mSignature.update(SECRET_MESSAGE.getBytes());
            return true;
        } catch (KeyPermanentlyInvalidatedException e) {
            return false;
        } catch (CertificateException | IOException
                | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to init Cipher", e);
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
            throw new RuntimeException("Failed to init Cipher", e);
        } catch (KeyStoreException e) {
            e.printStackTrace();
            throw new RuntimeException("Failed to init Cipher", e);
        }
    }

    public void onPurchased(boolean withFingerprint, FingerprintManager.AuthenticationResult result) {
        if (withFingerprint) {
            // If the user has authenticated with fingerprint, verify that using cryptography and
            // then show the confirmation message.
            tryEncrypt();
        } else {
            // Authentication happened with backup password. Just show the confirmation message.
            showConfirmation(null);
        }
    }

    // Show confirmation, if fingerprint was used show crypto information.
    private void showConfirmation(byte[] signed) {
        findViewById(R.id.confirmation_message).setVisibility(View.VISIBLE);
        if (signed != null) {
            TextView v = (TextView) findViewById(R.id.encrypted_message);
            v.setVisibility(View.VISIBLE);
            //signed
//            v.setText(Base64.encodeToString(signed, 0 /* flags */));
            //verified
            try {
                v.setText("" + verifyData(SECRET_MESSAGE, Base64.encodeToString(signed, 0 /* flags */)));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Tries to encrypt some data with the generated key in {@link #createKey} which is
     * only works if the user has just authenticated via fingerprint.
     */
    private void tryEncrypt() {
        try {
            //test another Signature
//            byte[] signed = testAttackByAnother();
//            test end
//            mSignature = result.getCryptoObject().getSignature();
            mSignature.update(SECRET_MESSAGE.getBytes());
            byte[] signed = mSignature.sign();
//            byte[] signed = mSignature.sign(SECRET_MESSAGE.getBytes());
            showConfirmation(signed);
        } catch (SignatureException e) {
            e.printStackTrace();
            Toast.makeText(this, "Failed to encrypt the data with the generated key. "
                    + "Retry the purchase", Toast.LENGTH_LONG).show();
//            Log.e(TAG, "Failed to encrypt the data with the generated key." + e.getMessage());
        }
    }

    private byte[] testAttackByAnother() {
        try {
            KeyStore fakeStore = KeyStore.getInstance("AndroidKeyStore");
            fakeStore.load(null);
            PrivateKey key = (PrivateKey) fakeStore.getKey(KEY_NAME, null);
//            mSignature.update(SECRET_MESSAGE.getBytes());
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initSign(key);
            s.update(SECRET_MESSAGE.getBytes());
            return s.sign();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Creates a symmetric key in the Android Key Store which can only be used after the user has
     * authenticated with fingerprint.
     *
     * @return {@code true} if key is created successful, {@code false} otherwise such as when no
     * fingerprints are registered.
     */
    public boolean createKey() {
        // The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
        // for your flow. Use of keys is necessary if you need to know if the set of
        // enrolled fingerprints has changed.
        try {
            mKeyStore.load(null);
            // Set the alias of the entry in Android KeyStore where the key will appear
            // and the constrains (purposes) in the constructor of the Builder
//            Calendar start = new GregorianCalendar();
//            Calendar end = new GregorianCalendar();
//            end.add(Calendar.YEAR, 1);
            //END_INCLUDE(create_valid_dates)


            // BEGIN_INCLUDE(create_spec)
            // The KeyPairGeneratorSpec object is how parameters for your key pair are passed
            // to the KeyPairGenerator.  For a fun home game, count how many classes in this sample
            // start with the phrase "KeyPair".

            KeyGenParameterSpec spec =
                    new KeyGenParameterSpec.Builder(KEY_NAME, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                            // You'll use the alias later to retrieve the key.  It's a key for the key!
                                    // The subject used for the self-signed certificate of the generated pair

                            .setDigests(KeyProperties.DIGEST_SHA256,
                                    KeyProperties.DIGEST_SHA384,
                                    KeyProperties.DIGEST_SHA512)
                                    // Date range of validity for the generated pair.
                            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
//                            .setKeyValidityStart(start.getTime())
//                            .setKeyValidityEnd(end.getTime())
                            .setUserAuthenticationRequired(true)
//                            .setUserAuthenticationValidityDurationSeconds(1 * 60)
                            .build();
            mKeyGenerator.initialize(spec);
            mKeyGenerator.generateKeyPair();
//            mKeyGenerator.generateKey();
            return true;
        } catch (IllegalStateException e) {
            // This happens when no fingerprints are registered.
            Toast.makeText(this,
                    "Go to 'Settings -> Security -> Fingerprint' and register at least one fingerprint",
                    Toast.LENGTH_LONG).show();
            return false;
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException
                | CertificateException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Given some data and a signature, uses the key pair stored in the Android Key Store to verify
     * that the data was signed by this application, using that key pair.
     *
     * @param input        The data to be verified.
     * @param signatureStr The signature provided for the data.
     * @return A boolean value telling you whether the signature is valid or not.
     */
    public boolean verifyData(String input, String signatureStr) throws KeyStoreException,
            CertificateException, NoSuchAlgorithmException, IOException,
            UnrecoverableEntryException, InvalidKeyException, SignatureException {
        byte[] data = input.getBytes();
        byte[] signature;
        // BEGIN_INCLUDE(decode_signature)

        // Make sure the signature string exists.  If not, bail out, nothing to do.

        if (signatureStr == null) {
            Log.w(TAG, "Invalid signature.");
            Log.w(TAG, "Exiting verifyData()...");
            return false;
        }

        try {
            // The signature is going to be examined as a byte array,
            // not as a base64 encoded string.
            signature = Base64.decode(signatureStr, Base64.DEFAULT);
        } catch (IllegalArgumentException e) {
            // signatureStr wasn't null, but might not have been encoded properly.
            // It's not a valid Base64 string.
            return false;
        }
        // END_INCLUDE(decode_signature)

        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");

        // Weird artifact of Java API.  If you don't have an InputStream to load, you still need
        // to call "load", or it'll crash.
        ks.load(null);

        // Load the key pair from the Android Key Store
        KeyStore.Entry entry = ks.getEntry(KEY_NAME, null);

        if (entry == null) {
            Log.w(TAG, "No key found under alias: " + KEY_NAME);
            Log.w(TAG, "Exiting verifyData()...");
            return false;
        }

        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            Log.w(TAG, "Not an instance of a PrivateKeyEntry");
            return false;
        }

        // This class doesn't actually represent the signature,
        // just the engine for creating/verifying signatures, using
        // the specified algorithm.
        Signature s = Signature.getInstance("SHA256withRSA");

        // BEGIN_INCLUDE(verify_data)
        // Verify the data.
        s.initVerify(((KeyStore.PrivateKeyEntry) entry).getCertificate());
        s.update(data);
        boolean valid = s.verify(signature);
        return valid;
        // END_INCLUDE(verify_data)
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();

        if (id == R.id.action_settings) {
            Intent intent = new Intent(this, SettingsActivity.class);
            startActivity(intent);
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
