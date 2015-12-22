package com.common.utils.encrypt.oneway;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5 {

    public static byte[] digest(byte[] data) throws NoSuchAlgorithmException{
        MessageDigest mDigest = MessageDigest.getInstance("MD5");
        byte[] values = mDigest.digest(data);
        return values;
    }

}
