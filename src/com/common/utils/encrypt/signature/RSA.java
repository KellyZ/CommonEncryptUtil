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
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyGenerator;

import com.common.utils.encrypt.encode.Base64;

public class RSA {

    private static final String ALGORIZHM = "RSA";
    private static final String SignareturAlgorizhm = "MD5withRSA";
    
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
    
    public static byte[] signature(byte[] data,String base64EncodePrivateKeyStr) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException{
        byte[] pbyte = Base64.decode(base64EncodePrivateKeyStr, Base64.NO_WRAP);
        PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(pbyte);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORIZHM);
        PrivateKey privateKey = keyFactory.generatePrivate(encodedKeySpec);
        
        Signature signature = Signature.getInstance(SignareturAlgorizhm);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }
    
    public static boolean verify(byte[] data,byte[] signData,String base64EncodePublicKeyStr) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException{
        byte[] pbyte = Base64.decode(base64EncodePublicKeyStr, Base64.NO_WRAP);
        X509EncodedKeySpec encodeKeySpec = new X509EncodedKeySpec(pbyte);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORIZHM);
        PublicKey publicKey = keyFactory.generatePublic(encodeKeySpec);
        
        Signature signature = Signature.getInstance(SignareturAlgorizhm);
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signData);
    }
}
