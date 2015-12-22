package com.common.utils.encrypt.exchange;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import com.common.utils.encrypt.encode.Base64;

public class DH {

    private static final String ALGORITHM = "DH";
    
    /**
     * 
     * @return String[2] 0:Base64 encode public key with NO_WRAP, 1:Base64 encode private key with NO_WRAP
     * @throws NoSuchAlgorithmException
     */
    public static String[] getClientExchangeKeys() throws NoSuchAlgorithmException{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(512);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publieKey = keyPair.getPublic();
        
        String[] keys = new String[2];
        keys[0] = Base64.encodeToString(publieKey.getEncoded(), Base64.NO_WRAP);
        keys[1] = Base64.encodeToString(privateKey.getEncoded(), Base64.NO_WRAP);
        return keys;
    }
    
    public static String[] getServerExchangeKeys(String clientPublicKeyWithBase64Str) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException{
        byte[] pbyte = Base64.decode(clientPublicKeyWithBase64Str, Base64.NO_WRAP);
        X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(pbyte);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM); 
        DHPublicKey clientPublicKey = (DHPublicKey)keyFactory.generatePublic(encodedKeySpec);
        DHParameterSpec parameterSpec = clientPublicKey.getParams();
        
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(parameterSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey serverPublicKey = keyPair.getPublic();
        PrivateKey serverPrivateKey = keyPair.getPrivate();
        
        String[] keys = new String[2];
        keys[0] = Base64.encodeToString(serverPublicKey.getEncoded(), Base64.NO_WRAP);
        keys[1] = Base64.encodeToString(serverPrivateKey.getEncoded(), Base64.NO_WRAP);
        return keys;
    }
    
    public static String getExchangeAESKey(String privateKeyWithBase64Str,String publicKeyWithBase64Str) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException{
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        
        byte[] privateKeyBytes = Base64.decode(privateKeyWithBase64Str, Base64.NO_WRAP);
        PKCS8EncodedKeySpec privateEncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(privateEncodedKeySpec);
        
        byte[] publicKeyBytes = Base64.decode(publicKeyWithBase64Str, Base64.NO_WRAP);
        X509EncodedKeySpec publicEncodedKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = keyFactory.generatePublic(publicEncodedKeySpec);
        
        KeyAgreement keyAgreement = KeyAgreement.getInstance(ALGORITHM);
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        
        SecretKey secretKey = keyAgreement.generateSecret("AES");
        String aesKey = Base64.encodeToString(secretKey.getEncoded(), Base64.NO_WRAP);
        return aesKey;
    }
    
}
