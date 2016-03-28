/**
 * © 2009-2012 Tex Toll Services, LLC
 */
package net.luisalbertogh.jcrypto.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 * Encryption/Decryption utilities.
 * 
 * @author lagarcia
 */
public class CryptoUtils {

    /** Salt for PBE generation. */
    private static final byte[] salt = {(byte) 0xc7, (byte) 0x83, (byte) 0x21, (byte) 0x9c, (byte) 0x6e, (byte) 0xc8,
            (byte) 0xfe, (byte) 0x90 };

    /** Iteration count for PBE generation. */
    private static final int count = 12;

    /** Asymmetric key size. */
    private static final int KEY_SIZE = 1024;

    /** Buffer size. */
    private static final int BUFFER_SIZE = 1024;

    /** Properties. */
    private static Properties providers;
    
    /** Cipher type. */
    public static enum CipherType {
        /** Symmetric cipher */
        SYMMETRIC(1),
        /** Asymmetric cipher */
        ASYMMETRIC(2);

        /** Value. */
        public int value;

        /** Constructor */
        CipherType(int value) {
            this.value = value;
        }
    }

    /**
     * My key pair.
     * 
     * @author lagarcia
     */
    private static class MyKeyPair {
        public static PublicKey pubKey;
        public static PrivateKey privKey;
    }

    /**
     * Encrypt file content.
     * 
     * @param file - The original file
     * @param destFile - The file destination
     * @param algorithm - The algorithm
     * @param password - The password
     * @param cipherType - The cipher type (symmetric or asymmetric)
     * @return 0 when succeeded, otherwise -1
     * @throws Exception
     */
    public static int encryptFile(String file, String destFile, String algorithm, char[] password, int cipherType)
            throws Exception {    	
        return useCipherOnFile(file, destFile, algorithm, password, Cipher.ENCRYPT_MODE, cipherType);
    }

    /**
     * Encrypt file content.
     * 
     * @param file - The original file
     * @param destFile - The file destination
     * @param algorithm - The algorithm
     * @param password - The password
     * @param cipherType - The cipher type (symmetric or asymmetric)
     * @return 0 when succeeded, otherwise -1
     * @throws Exception
     */
    public static int decryptFile(String file, String destFile, String algorithm, char[] password, int cipherType)
            throws Exception {
        return useCipherOnFile(file, destFile, algorithm, password, Cipher.DECRYPT_MODE, cipherType);
    }

    /**
     * Use cipher to encrypt or decrypt.
     * 
     * @param file - The input file
     * @param destFile - The output file
     * @param algorithm - The algorithm
     * @param password - the password
     * @param cipherMode - The cipher mode
     * @param cipherType - The cipher type (symmetric or asymmetric)
     * @return 0 if succeeded
     * @throws Exception
     */
    private static int useCipherOnFile(String file, String destFile, String algorithm, char[] password, int cipherMode,
            int cipherType) throws Exception {
        /* File to encrypt */
        File f = new File(file);

        /* Destination file */
        File dest = new File(destFile);

        Cipher cipher = null;
        /* Get symmetric cipher */
        if (CipherType.SYMMETRIC.value == cipherType) {
            cipher = getCipher(algorithm, password, cipherMode);
        }
        /* Get asymmetric cipher */
        else {
            cipher = getAsymmetricCipher(algorithm, cipherMode);
        }

        /* Encrypt */
        byte[] buffer = new byte[BUFFER_SIZE];

        /* Output stream for encrypted file */
        CipherOutputStream cos = new CipherOutputStream(new FileOutputStream(dest), cipher);

        /* Read from original file */
        FileInputStream fis = new FileInputStream(f);
        int bytesRead = -1;
        int maxBytes = (KEY_SIZE / 8) - 11;
        boolean cipherAsymmetric = (CipherType.ASYMMETRIC.value == cipherType);
        while ((bytesRead = fis.read(buffer)) != -1) {
            /* If cipher is asymmetric and bytesRead > (key_size/8)-11 --> Exception */
            if (cipherAsymmetric && (bytesRead > maxBytes)) {
                throw new Exception("Asymmetric key size is smaller than read bytes.");
            }

            /* Write encrypted to destination file */
            cos.write(buffer, 0, bytesRead);
            cos.flush();
        }

        fis.close();
        cos.close();

        return 0;
    }

    /**
     * Encrypt the text.
     * 
     * @param text - The text to encrypt
     * @param algorithm - The algorithm name
     * @param password - The password
     * @return The encrypted text in hexadecimal format
     * @throws Exception
     */
    public static String encrypt(String text, String algorithm, char[] password) throws Exception {
        return useCipher(text, algorithm, password, Cipher.ENCRYPT_MODE);
    }

    /**
     * Decrypt the text.
     * 
     * @param text - The text to encrypt
     * @param algorithm - The algorithm name
     * @param password - The password
     * @return The encrypted text in hexadecimal format
     * @throws Exception
     */
    public static String decrypt(String text, String algorithm, char[] password) throws Exception {
        return useCipher(text, algorithm, password, Cipher.DECRYPT_MODE);
    }

    /**
     * Encrypt the text using RSA.
     * 
     * @param text - The text to encrypt
     * @param algorithm - The algorithm name
     * @return The encrypted text in hexadecimal format
     * @throws Exception
     */
    public static String encrypt(String text, String algorithm) throws Exception {
        return useAsymmetricCipher(text, algorithm, Cipher.ENCRYPT_MODE);
    }

    /**
     * Decrypt the text using RSA.
     * 
     * @param text - The text to encrypt
     * @param algorithm - The algorithm name
     * @return The encrypted text in hexadecimal format
     * @throws Exception
     */
    public static String decrypt(String text, String algorithm) throws Exception {
        return useAsymmetricCipher(text, algorithm, Cipher.DECRYPT_MODE);
    }

    /**
     * Use RSA cipher to encrypt or decrypt the text.
     * 
     * @param text - The text to encrypt
     * @param algorithm - The algorithm name
     * @param cipherMode - Cipher mode (encrypt or decrypt)
     * @return The encrypted text in hexadecimal format
     * @throws Exception
     */
    public static String useAsymmetricCipher(String text, String algorithm, int cipherMode) throws Exception {    	
    	/* Algorithm */
        Cipher cipher = getAsymmetricCipher(algorithm, cipherMode);

        /* Encrypted/decrypted text */
        String encryptedText = "";

        /* Encrypt */
        if (cipherMode == Cipher.ENCRYPT_MODE) {
            byte[] data = text.getBytes("UTF8");
            byte[] encrypted = cipher.doFinal(data);
            encryptedText = new BASE64Encoder().encode(encrypted);
        }
        /* Decrypt */
        else if (cipherMode == Cipher.DECRYPT_MODE) {
            byte[] encrypted = new BASE64Decoder().decodeBuffer(text);
            byte[] data = cipher.doFinal(encrypted);
            encryptedText = new String(data);
        }

        return encryptedText;
    }

    /**
     * Use cipher to encrypt or decrypt the text.
     * 
     * @param text - The text to encrypt
     * @param algorithm - The algorithm name
     * @param password - The password
     * @param cipherMode - Cipher mode (encrypt or decrypt)
     * @return The encrypted text in hexadecimal format
     * @throws Exception
     */
    public static String useCipher(String text, String algorithm, char[] password, int cipherMode) throws Exception {
        String encText = "";

        /* Encrypted bytes */
        byte[] encrypted = null;

        /* Get cipher */
        Cipher cipher = getCipher(algorithm, password, cipherMode);

        /* Encrypt or decrypt */
        if (cipherMode == Cipher.ENCRYPT_MODE) {
            byte[] data = text.getBytes("UTF8");
            encrypted = cipher.doFinal(data);
            encText = new BASE64Encoder().encode(encrypted);
        } else if (cipherMode == Cipher.DECRYPT_MODE) {
            byte[] data = new BASE64Decoder().decodeBuffer(text);
            encrypted = cipher.doFinal(data);
            encText = new String(encrypted);
        }

        return encText;
    }

    /**
     * Create cipher to encrypt or decrypt using asymmetric algoritm (like RSA).
     * 
     * @param algorithm - The algorithm
     * @param password - The password
     * @param cipherMode - The cipher mode
     * @return The cipher object
     * @throws Exception
     */
    private static Cipher getAsymmetricCipher(String algorithm, int cipherMode) throws Exception {
        /* Algorithm */
        Cipher cipher = Cipher.getInstance(algorithm);

        /* Generate public and private keys */
        if (MyKeyPair.pubKey == null || MyKeyPair.privKey == null) {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
            keyGen.initialize(KEY_SIZE); // Key size
            KeyPair kp = keyGen.genKeyPair();
            MyKeyPair.pubKey = kp.getPublic();
            MyKeyPair.privKey = kp.getPrivate();
        }

        /* Encrypt */
        if (cipherMode == Cipher.ENCRYPT_MODE) {
            cipher.init(cipherMode, MyKeyPair.pubKey);
        }
        /* Decrypt */
        else if (cipherMode == Cipher.DECRYPT_MODE) {
            cipher.init(cipherMode, MyKeyPair.privKey);
        }

        return cipher;
    }

    /**
     * Create cipher to encrypt or decrypt.
     * 
     * @param algorithm - The algorithm
     * @param password - The password
     * @param cipherMode - The cipher mode
     * @return The cipher object
     * @throws Exception
     */
    private static Cipher getCipher(String algorithm, char[] password, int cipherMode) throws Exception {
        /* Algorithm */
        Cipher cipher = Cipher.getInstance(algorithm);

        /* Password exists and is not empty */
        if (password != null && password.length > 0) {
            /* Use Password Base encryption */
            if (algorithm.indexOf("PBE") != -1) {
                Map<String, Object> pbeMap = getPBEKey(algorithm, password);
                cipher.init(cipherMode, (SecretKey) pbeMap.get("key"), (PBEParameterSpec) pbeMap.get("params"));
            }
            /* DES - Minimum 8 chars length password */
            else if(algorithm.indexOf("DES") != -1){
            	String pwdStr = new String(password);
            	if(pwdStr.length() < 8){
            		throw new Exception("Password minimum length is 8 characters.");
            	}
                byte[] keyBytes = pwdStr.getBytes();
                DESKeySpec dsKey = new DESKeySpec(keyBytes);
                SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
        		SecretKey secretKey = skf.generateSecret(dsKey);
                cipher.init(cipherMode, secretKey);
            } 
            /* AES & others - Generate password using PBE */
            else {
            	/* Create secrete key */
                PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, 65536, 256);
                SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
                SecretKeySpec secretKey = new SecretKeySpec(pbeKey.getEncoded(), algorithm);
                cipher.init(cipherMode, secretKey);
            }
        }
        /* No password available */
        else {
            SecretKeySpec secretKey = getSecretKey(algorithm);
            cipher.init(cipherMode, secretKey);
        }

        return cipher;
    }

    /**
     * Get secret key.
     * 
     * @param algorithm - Algorithm name
     * @return The secret key
     * @throws NoSuchAlgorithmException
     */
    private static SecretKeySpec getSecretKey(String algorithm) throws NoSuchAlgorithmException {
        KeyGenerator kgen = KeyGenerator.getInstance(algorithm);
        SecretKey skey = kgen.generateKey();
        byte[] raw = skey.getEncoded();
        return new SecretKeySpec(raw, algorithm);
    }

    /**
     * Get PBE key.
     * 
     * @param algorithm - The algorithm name
     * @param password - The password string
     * @return Map with PBE key and params
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static Map<String, Object> getPBEKey(String algorithm, char[] password) throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        Map<String, Object> pbeMap = new HashMap<String, Object>();

        /* Create PBE parameter set */
        PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, count);
        pbeMap.put("params", pbeParamSpec);

        /* Create secrete key */
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password);
        SecretKeyFactory keyFac = SecretKeyFactory.getInstance(algorithm);
        SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
        pbeMap.put("key", pbeKey);

        return pbeMap;
    }

    /**
     * Load key pair from keystore file.
     * 
     * @param keystoreFile - The keystore file
     * @param passwd - The keystore password
     * @throws Exception
     */
    public static void loadKeysFromKeyStore(File keystoreFile, char[] passwd) throws Exception {
    	/* Load properties file */
    	loadProperties();
    	
        /* Load default type keystore */
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

        /* Load the keystore */
        FileInputStream fis = new FileInputStream(keystoreFile);
        ks.load(fis, passwd);

        /* Get the private key */
        PrivateKey privKey = (PrivateKey) ks.getKey(providers.getProperty("keyname"), passwd);

        /* Get the public key */
        PublicKey pubKey = ks.getCertificate(providers.getProperty("keyname")).getPublicKey();

        /* Set keys for encryption */
        MyKeyPair.privKey = privKey;
        MyKeyPair.pubKey = pubKey;
    }

    /**
     * Find available message digest algorithms.
     * 
     * @param providerName - The JCA provider name
     * @return The message digesters list
     */
    public static List<String> findMessageDigesters(String providerName) {
        List<String> mds = new ArrayList<String>();
        Provider[] providers = Security.getProviders();
        for (Provider prov : providers) {
            /* Check provider name if requested */
            String provName = prov.getName();
            if (providerName != null && !provName.equals(providerName)) {
                /* Next provider */
                continue;
            }

            Set<Object> keys = prov.keySet();
            for (Object key : keys) {
                String keyStr = (String) key;
                if (keyStr.startsWith("MessageDigest.")) {
                    mds.add(keyStr.substring("MessageDigest.".length()));
                }
            }
        }

        /* Sort it out */
        Collections.sort(mds);

        return mds;
    }

    /**
     * Generate a digested password.
     * 
     * @param password - The password to digest
     * @param algorithm - The algorithm
     * @return The digested password
     */
    public static String digestPassword(String password, String algorithm) {
        String digested = "";
        try {
            /* Digest password */
            MessageDigest md = MessageDigest.getInstance(algorithm);
            md.update(password.getBytes());
            byte byteData[] = md.digest();

            /* Convert to HEX format */
            digested = convertToHex(byteData);
        } catch (Exception ex) {
            ex.printStackTrace();
            return "Error: " + ex.getMessage();
        }

        return digested;
    }

    /**
     * Find available message digest algorithms.
     * 
     * @param providerName - The JCA provider name
     * @return The message digesters list
     */
    public static List<String> findAlgorithms(String providerName) {
        List<String> mds = new ArrayList<String>();
        Provider[] providers = Security.getProviders();
        for (Provider prov : providers) {
            /* Check provider name if requested */
            String provName = prov.getName();
            if (providerName != null && !provName.equals(providerName)) {
                /* Next provider */
                continue;
            }

            Set<Object> keys = prov.keySet();
            for (Object key : keys) {
                String keyStr = (String) key;
                if (keyStr.startsWith("Cipher.")) {
                    String name = keyStr.substring("Cipher.".length());
                    if (!mds.contains(name)) {
                        mds.add(name);
                    }
                }
            }
        }

        /* Order list */
        Collections.sort(mds);

        return mds;
    }

    /**
     * Find JDK providers list.
     * 
     * @return - The providers names list
     */
    public static List<String> findProviders() {
        List<String> providerNames = new ArrayList<String>();

        /* Providers */
        Provider[] providers = Security.getProviders();
        for (Provider prov : providers) {
            String provName = prov.getName();
            providerNames.add(provName);
        }

        /* Order list */
        Collections.sort(providerNames);

        return providerNames;
    }

    /**
     * Replace text.
     * 
     * @param text
     * @return The new text
     */
    private static String replace(String text, String oldText, String newText) {
        if (text != null) {
            return text.replace(oldText, newText);
        }

        return null;
    }

    /**
     * Convert from byte to hexadecimal format.
     * 
     * @param byteData - The byte array
     * @return The string in hexadecimal
     */
    private static String convertToHex(byte[] byteData) {
        /* Convert to HEX format */
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < byteData.length; i++) {
            sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
        }

        return sb.toString();
    }
    
    /**
     * Load properties.
     * @throws IOException 
     * @throws FileNotFoundException 
     */
    private static void loadProperties() throws FileNotFoundException, IOException{
    	/** Load properties */
    	if(providers == null) {
	    	providers = new Properties();
	        providers.load(new FileReader("config/providers.properties"));
    	}
    }
}
