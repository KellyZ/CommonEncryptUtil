package com.common.utils.encrypt;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.common.utils.encrypt.asymmetric.RSA;
import com.common.utils.encrypt.exchange.DH;
import com.common.utils.encrypt.signature.DSA;
import com.common.utils.encrypt.signature.ECDSA;

public class Test {

    /**
     * @param args
     */
    public static void main(String[] args) {
        
        // signature
        try {
            String[] keys = DSA.getDSAKeyPair();
            
            String publicKeyBase64EncodeStr = "MIHxMIGoBgcqhkjOOAQBMIGcAkEA/KaCzo4Syrom78z3EQ5SbbB4sF7ey80etKII864WF64B81uRpH5t9jQTxeEu0ImbzRMqzVDZkVG9xD7nN1kuFwIVAJYu3cw2nLqOuyYO5rahJtk0bjjFAkBnhHGyepz0TukaScUUfbGpqvJE8FpDTWSGkx0tFCcbnjUDC3H9c9oXkGmzLik1Yw4cIGI1TQ2iCmxBblC+eUykA0QAAkEA8d3b83p1LyLVUe74wp4oe3+7w/Rw6PAieTLT0Qrdr+PbKytML2u+PPGOYSyEJtvN4Lep5pj9Ax83zIBVRBlbhg==";
            String privateKeyBase64EncodeStr = "MIHGAgEAMIGoBgcqhkjOOAQBMIGcAkEA/KaCzo4Syrom78z3EQ5SbbB4sF7ey80etKII864WF64B81uRpH5t9jQTxeEu0ImbzRMqzVDZkVG9xD7nN1kuFwIVAJYu3cw2nLqOuyYO5rahJtk0bjjFAkBnhHGyepz0TukaScUUfbGpqvJE8FpDTWSGkx0tFCcbnjUDC3H9c9oXkGmzLik1Yw4cIGI1TQ2iCmxBblC+eUykBBYCFCKfE9iQjbifYLE/2/CScHbhpku9";
            System.out.println("keys:"+keys[0]+",\n"+keys[1]);
            
            byte[] srcData = "DH test server public key".getBytes();
            try {
                byte[] signData = DSA.signature(srcData, privateKeyBase64EncodeStr);
                boolean verify = DSA.verify(srcData, signData, publicKeyBase64EncodeStr);
                
                System.out.println("verify result:"+verify);
            } catch (InvalidKeyException | InvalidKeySpecException
                    | SignatureException e) {
                e.printStackTrace();
            }
            
            keys = ECDSA.generateKeyPair();
            System.out.println("keys:"+keys[0]+",\n"+keys[1]);
            publicKeyBase64EncodeStr = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmtuaqAR66JDpauZ8Ulzm4nGZS0QhGaGTj3QHK4ST5vpCdm8J2r74uzh8TMPUduoTQp2zPopwF18vzi5ssWAcAg==";
            privateKeyBase64EncodeStr = "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCCLrtOD695dFYhNujGuy1yufDTxk6kaNktnL5KLR70aCw==";
            try {
                byte[] ecdsaSignData = ECDSA.signature(srcData, privateKeyBase64EncodeStr);
                boolean ecdsaVerify = ECDSA.verify(srcData, ecdsaSignData, publicKeyBase64EncodeStr);
                System.out.println("ecdsa verify result:"+ecdsaVerify);
            } catch (InvalidKeyException | InvalidKeySpecException
                    | SignatureException e) {
                e.printStackTrace();
            }
            
            
            
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        
        // exchange
        try {
            String[] clientKeys = DH.getClientExchangeKeys();
            String[] serverKeys = DH.getServerExchangeKeys(clientKeys[0]);
            
            String clientAesKey = DH.getExchangeAESKey(clientKeys[1], serverKeys[0]);
            String serverAesKey = DH.getExchangeAESKey(serverKeys[1], clientKeys[0]);
            
            System.out.println("clientAesKey:"+clientAesKey);
            System.out.println("serverAesKey:"+serverAesKey);
            
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            e.printStackTrace();
        }
        
        // RSA encrypt & decrypt
        try {
            String[] keyPair = RSA.generateKeyPair();
            String srcData = "RSA encrypt&decrypt test";
            
            byte[] encryptData = RSA.encryptWithPrivateKey(srcData.getBytes(), keyPair[1]);
            byte[] decryptData = RSA.decryptWithPublicKey(encryptData, keyPair[0]);
            System.out.println("decrypt with public key:"+new String(decryptData));
            
            encryptData = RSA.encryptWithPublicKey(srcData.getBytes(), keyPair[0]);
            decryptData = RSA.decryptWithPrivateKey(encryptData, keyPair[1]);
            System.out.println("decrypt with private key:"+new String(decryptData));
            
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
    }

}
