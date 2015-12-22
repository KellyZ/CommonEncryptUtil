package com.common.utils.encrypt.oneway;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class MAC {

    private static final String ALGORITHM = "HmacMD5";
    
    public static byte[] getRandomHMACKey() throws NoSuchAlgorithmException{
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        SecretKey key = keyGenerator.generateKey();
        return key.getEncoded();
    }
    
    public static byte[] encrypt(byte[] data,byte[] key) throws NoSuchAlgorithmException, InvalidKeyException{
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM);
        Mac mac = Mac.getInstance(ALGORITHM);
        mac.init(secretKeySpec);
        
        return mac.doFinal(data);
    }
}
