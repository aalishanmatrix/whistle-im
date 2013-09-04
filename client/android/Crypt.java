/**
 * whistle.im Android cryptography library
 * Copyright (C) 2013 Daniel Wirtz - http://dcode.io
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package im.whistle.crypt;

import android.util.Base64;
import android.util.Log;
import im.whistle.util.AsyncCallback;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.json.JSONArray;

/**
 * Native crypt for Android.
 * @author Daniel Wirtz <dcode@dcode.io>
 */
public class Crypt {
    
    // We are using a thread pool internally, so all operations herein are
    // simply synchronous.
    
    /**
     * RSA bits.
     */
    public final static int RSA_BITS = 2048;
    
    /**
     * RSA bytes.
     */
    public final static int RSA_BYTES = RSA_BITS/8;
    
    /**
     * AES bits.
     */
    public final static int AES_BITS = 256;
    
    /**
     * AES bytes.
     */
    public final static int AES_BYTES = AES_BITS/8;
    
    /**
     * Generates a private/public key pair.
     * @param args Arguments, element at 0 is the key size
     * @param callback Callback
     */
    public static void genkeys(JSONArray args, AsyncCallback<JSONArray> callback) {
        try {
            Log.i("whistle", "Generating key pair ...");
            PRNGProvider.init(); // Ensure OpenSSL fix
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            int bits = args.getInt(0);
            int exp = args.getInt(1);
            keyPairGenerator.initialize(new RSAKeyGenParameterSpec(bits, BigInteger.valueOf(exp)));
            KeyPair keyPair = keyPairGenerator.genKeyPair();
            String priv = "-----BEGIN RSA PRIVATE KEY-----\n"
                    + Base64.encodeToString(keyPair.getPrivate().getEncoded(), Base64.DEFAULT).trim()
                    + "\n-----END RSA PRIVATE KEY-----";
            String pub = "-----BEGIN PUBLIC KEY-----\n"
                    + Base64.encodeToString(keyPair.getPublic().getEncoded(), Base64.DEFAULT).trim()
                    + "\n-----END PUBLIC KEY-----";
            JSONArray res = new JSONArray();
            res.put(priv);
            res.put(pub);
            callback.success(res);
        } catch (Exception ex) {
            Log.w("whistle", "Key pair generation failed: "+ex.getMessage());
            callback.error(ex);
        }
    }
    
    /**
     * Strips a key to pure base64.
     * @param key Key to strip
     * @return Stripped key
     */
    public static String stripKey(String key) {
        return key.replaceAll("\\-\\-\\-\\-\\-[^\\-]+\\-\\-\\-\\-\\-\\s*", "");
    }
    
    /**
     * Encrypts a message.
     * @param args Arguments: data, publicKey[, privateKey]
     * @param callback Callback
     */
    public static void encrypt(JSONArray args, AsyncCallback<JSONArray> callback) {
        try {
            PRNGProvider.init(); // Ensure OpenSSL fix
            
            // Get the arguments
            String data = args.getString(0);
            String pub = args.getString(1);
            String priv = null;
            if (args.length() == 3) {
                priv = args.getString(2);
            }
            String sig = null;
            
            // Convert everything into byte arrays
            byte[] dataRaw = data.getBytes("utf-8");
            byte[] pubRaw = Base64.decode(stripKey(pub), Base64.DEFAULT);
            
            // Generate random AES key and IV
            byte[] aesKey = new byte[AES_BYTES];
            new SecureRandom().nextBytes(aesKey);
            byte[] aesIv = new byte[16]; // Block size
            new SecureRandom().nextBytes(aesIv);
            Cipher c  = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new IvParameterSpec(aesIv));
            
            // Encrypt data with AES
            byte[] encData = c.doFinal(dataRaw);
            
            // Encrypt aes data with RSA
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pubRaw);
            KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
            c = Cipher.getInstance("RSA/None/OAEPWithSHA-1AndMGF1Padding", "BC");
            c.init(Cipher.ENCRYPT_MODE, kf.generatePublic(publicKeySpec));
            c.update(aesKey);
            c.update(aesIv);
            byte[] encKey = c.doFinal();
            
            // Concatenate and transform
            byte[] encRaw = new byte[encKey.length + encData.length];
            System.arraycopy(encKey, 0, encRaw, 0, encKey.length);
            System.arraycopy(encData, 0, encRaw, encKey.length, encData.length);
            encKey = null; encData = null;
            String enc = new String(Base64.encode(encRaw /* needed for sign */, Base64.NO_WRAP), "utf-8");
            
            // Sign
            if (priv != null) {
                // Fail on error (no try-catch)
                byte[] privRaw = Base64.decode(stripKey(priv), Base64.DEFAULT);
                PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privRaw);
                Signature s = Signature.getInstance("SHA1withRSA", "BC");
                s.initSign(kf.generatePrivate(privateKeySpec));
                s.update(encRaw);
                sig = new String(Base64.encode(s.sign(), Base64.NO_WRAP), "utf-8");
            }
            
            JSONArray res = new JSONArray();
            res.put(enc);
            res.put(sig);
            callback.success(res);
        } catch (Exception ex) {
            Log.w("whistle", "Encrypt error: "+ex.getMessage(), ex);
            callback.error(ex);
        }
    }
    
    /**
     * Decrypts a message.
     * @param args Arguments: enc, privateKey, sig, publicKey
     * @param callback Callback
     */
    public static void decrypt(JSONArray args, AsyncCallback<JSONArray> callback) {
        try {            
            // Get the arguments
            String enc = args.getString(0);
            String key = args.getString(1);
            String sig = null;
            String pub = null;
            if (args.length() == 4) {
                sig = args.getString(2);
                pub = args.getString(3);
            }
            Boolean ver = null;
            
            // Convert everything into byte arrays
            byte[] encRaw = Base64.decode(enc, Base64.DEFAULT);
            byte[] keyRaw = Base64.decode(stripKey(key), Base64.DEFAULT);

            // Verify signature
            if (sig != null && pub != null) {
                try {
                    byte[] sigRaw = Base64.decode(sig, Base64.DEFAULT);
                    byte[] pubRaw = Base64.decode(stripKey(pub), Base64.DEFAULT);
                    X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pubRaw);
                    KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
                    Signature s = Signature.getInstance("SHA1withRSA", "BC");
                    s.initVerify(kf.generatePublic(publicKeySpec));
                    s.update(encRaw);
                    ver = s.verify(sigRaw);
                } catch (Exception ex) {
                    Log.i("whistle", "Verification failed: "+ex.getMessage());
                    ver = false;
                }
            }
            
            // Split enc into encrypted aes data and remaining enc
            byte[] encSplit = encRaw;
            byte[] aesRaw = new byte[RSA_BYTES];
            System.arraycopy(encSplit, 0, aesRaw, 0, aesRaw.length);
            encRaw = new byte[encSplit.length-RSA_BYTES];
            System.arraycopy(encSplit, RSA_BYTES, encRaw, 0, encRaw.length);
            
            // Decrypt encrypted aes data using RSAES-OAEP
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyRaw);
            KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
            Cipher c = Cipher.getInstance("RSA/None/OAEPWithSHA-1AndMGF1Padding");
            c.init(Cipher.DECRYPT_MODE, kf.generatePrivate(privateKeySpec));
            aesRaw = c.doFinal(aesRaw);
            
            // Decrypted enc using AES-CBC
            byte[] aesKey = new byte[AES_BYTES];
            byte[] aesIv = new byte[aesRaw.length-aesKey.length];
            System.arraycopy(aesRaw, 0, aesKey, 0, aesKey.length);
            System.arraycopy(aesRaw, aesKey.length, aesIv, 0, aesIv.length);
            c = Cipher.getInstance("AES/CBC/PKCS7Padding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new IvParameterSpec(aesIv));
            byte[] dec = c.doFinal(encRaw);
            
            JSONArray res = new JSONArray();
            res.put(new String(dec, "utf-8"));
            res.put(ver);
            callback.success(res);
        } catch (Exception ex) {
            Log.w("whistle", "Decrypt error:"+ex.getMessage(), ex);
            callback.error(ex);
        }
    }
    
    /**
     * Hashes a password.
     * @param args Arguments: password, saltOrLogRounds
     * @param callback Callback
     */
    public static void hash(JSONArray args, AsyncCallback<String> callback) {
        try {
            PRNGProvider.init(); // Ensure OpenSSL fix
            String pass = args.getString(0);
            int rounds = args.optInt(1, 0);
            String salt;
            if (rounds > 0) {
                salt = Bcrypt.gensalt(rounds);
            } else {
                salt = args.getString(1);
            }
            callback.success(Bcrypt.hashpw(pass, salt));
        } catch (Exception ex) {
            Log.w("whistle", "Hash error: "+ex.getMessage(), ex);
            callback.error(ex);
        }
    }
}
