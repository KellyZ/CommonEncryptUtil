package com.common.utils.encrypt.asymmetric;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.common.utils.encrypt.encode.Base64;

public class RSA {
    private static final String ALGORIZHM = "RSA";
    
    /**
     * 
     * @return String[2]: 0:Base64 encode public key with NO_WRAP, 1:Base64 encode private key with NO_WRAP
     * @throws NoSuchAlgorithmException
     */
    public static String[] generateKeyPair() throws NoSuchAlgorithmException{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORIZHM);
        keyPairGenerator.initialize(512);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();
        
        String[] result = new String[2];
        result[0] = Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP);
        result[1] = Base64.encodeToString(privateKey.getEncoded(), Base64.NO_WRAP);
        return result;
    }
    
    public static byte[] encryptWithPrivateKey(byte[] data,String privateKeyWithBase64Str) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        byte[] pbytes = Base64.decode(privateKeyWithBase64Str, Base64.NO_WRAP);
        PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(pbytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORIZHM);
        PrivateKey privateKey = keyFactory.generatePrivate(encodedKeySpec);
        
        Cipher cipher = Cipher.getInstance(ALGORIZHM);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        
        return cipher.doFinal(data);
    }
    
    public static byte[] decryptWithPublicKey(byte[] encryptData,String publicKeyWithBase64Str) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        byte[] pbytes = Base64.decode(publicKeyWithBase64Str, Base64.NO_WRAP);
        X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(pbytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORIZHM);
        PublicKey publicKey = keyFactory.generatePublic(encodedKeySpec);
        
        Cipher cipher = Cipher.getInstance(ALGORIZHM);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        
        return cipher.doFinal(encryptData);
    }
    
    public static byte[] encryptWithPublicKey(byte[] data,String publicKeyWithBase64Str) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        byte[] pbytes = Base64.decode(publicKeyWithBase64Str, Base64.NO_WRAP);
        X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(pbytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORIZHM);
        PublicKey publicKey = keyFactory.generatePublic(encodedKeySpec);
        
        Cipher cipher = Cipher.getInstance(ALGORIZHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        
        return cipher.doFinal(data);
    }
    
    public static byte[] decryptWithPrivateKey(byte[] encryptData,String privateKeyWithBase64Str) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        byte[] pbytes = Base64.decode(privateKeyWithBase64Str, Base64.NO_WRAP);
        PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(pbytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORIZHM);
        PrivateKey privateKey = keyFactory.generatePrivate(encodedKeySpec);
        
        Cipher cipher = Cipher.getInstance(ALGORIZHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        
        return cipher.doFinal(encryptData);
    }
}
