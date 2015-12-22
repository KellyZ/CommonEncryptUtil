package com.common.utils.encrypt.oneway;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA {

    public static byte[] digest(byte[] data) throws NoSuchAlgorithmException{
        MessageDigest digest = MessageDigest.getInstance("SHA"); //SHA-256  SHA-512
        byte[] values = digest.digest(data);
        return values;
    }

}
