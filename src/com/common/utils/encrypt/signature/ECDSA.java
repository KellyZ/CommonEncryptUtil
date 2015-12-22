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
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import com.common.utils.encrypt.encode.Base64;

public class ECDSA {

    private static final String ALGORIZHM = "EC";
    private static final String SignareturAlgorizhm = "SHA1withECDSA";
    
    /**
     * 
     * @return String[2] 0:Base64 encode public key with NO_WRAP, 1:Base64 encode private key with NO_WRAP
     * @throws NoSuchAlgorithmException
     */
    public static String[] generateKeyPair() throws NoSuchAlgorithmException{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORIZHM);
        keyPairGenerator.initialize(256);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        ECPublicKey publicKey = (ECPublicKey)keyPair.getPublic();
        ECPrivateKey privateKey = (ECPrivateKey)keyPair.getPrivate();
        
        String[] result = new String[2];
        result[0] = Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP);
        result[1] = Base64.encodeToString(privateKey.getEncoded(), Base64.NO_WRAP);
        
        return result;
    }
    
    /**
     * 
     * @param data
     * @param base64EncodePrivateKeyStr: Base64 encode with NO_WRAP
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
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
    
    /**
     * 
     * @param data
     * @param signData
     * @param base64EncodePublicKeyStr: Base64 encode with NO_WRAP
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static boolean verify(byte[] data,byte[] signData,String base64EncodePublicKeyStr) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException{
        byte[] pbyte = Base64.decode(base64EncodePublicKeyStr, Base64.NO_WRAP);
        X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(pbyte);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORIZHM);
        PublicKey publicKey = keyFactory.generatePublic(encodedKeySpec);
        
        Signature signature = Signature.getInstance(SignareturAlgorizhm);
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signData);
    }
}
