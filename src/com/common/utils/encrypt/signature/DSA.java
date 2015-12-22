package com.common.utils.encrypt.signature;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import com.common.utils.encrypt.encode.Base64;


public class DSA {

    /**
     * 
     * @return String[] 0:base64 NO_WRAP public key string, 1:base64 NO_WRAP private key string
     * @throws NoSuchAlgorithmException
     */
    public static String[] getDSAKeyPair() throws NoSuchAlgorithmException{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(512);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        DSAPublicKey publicKey = (DSAPublicKey)keyPair.getPublic();
        DSAPrivateKey privateKey = (DSAPrivateKey)keyPair.getPrivate();
        
        String[] result = new String[2];
        result[0] = Base64.encodeToString(publicKey.getEncoded(),Base64.NO_WRAP);
        result[1] = Base64.encodeToString(privateKey.getEncoded(), Base64.NO_WRAP);
        return result;
    }
    
    /**
     * 
     * @param data
     * @param privateKeyStr Base64 encode with NO_WRAP
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static byte[] signature(byte[] data,String privateKeyStr) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException{
        byte[] pbyte = Base64.decode(privateKeyStr, Base64.NO_WRAP);
        PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(pbyte);
        KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        PrivateKey privateKey = keyFactory.generatePrivate(encodedKeySpec);
        
        Signature signature = Signature.getInstance("SHA1withDSA");
        signature.initSign(privateKey);
        signature.update(data);
        
        return signature.sign();
    }
    
    /**
     * 
     * @param data
     * @param signedData
     * @param publicKeyStr Base64 encode with NO_WRAP
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static boolean verify(byte[] data,byte[] signedData,String publicKeyStr) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        byte[] pbyte = Base64.decode(publicKeyStr, Base64.NO_WRAP);
        X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(pbyte);
        KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        PublicKey publicKey = keyFactory.generatePublic(encodedKeySpec);
        
        Signature signature = Signature.getInstance("SHA1withDSA");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signedData);
    }
}
