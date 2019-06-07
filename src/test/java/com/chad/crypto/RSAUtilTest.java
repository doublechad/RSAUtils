package com.chad.crypto;


import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.*;

public class RSAUtilTest {

    @Test
    public void test() throws Exception {
        String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCdYE4557jOqI6K1M+es8AgAr39\n" +
                "nNEd7zE97K4Z0KzbuhP4Jn7BjTqZVRfW77bnKhz8nhqNvky7hByih+0eGa+K2SuH\n" +
                "ZrvtckhIZPseqaJkfPKnl/IbpmiKsqFbKxf8qIrKI8UgAtTuOOq4QS+Z+5pnQWYu\n" +
                "+SirAPJuAmvXunrkKQIDAQAB";

        String privateKey = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAJ1gTjnnuM6ojorU\n" +
                "z56zwCACvf2c0R3vMT3srhnQrNu6E/gmfsGNOplVF9bvtucqHPyeGo2+TLuEHKKH\n" +
                "7R4Zr4rZK4dmu+1ySEhk+x6pomR88qeX8humaIqyoVsrF/yoisojxSAC1O446rhB\n" +
                "L5n7mmdBZi75KKsA8m4Ca9e6euQpAgMBAAECgYADUs1UG7ijZJveArB/wXwFMQmi\n" +
                "GXWxFCQOErl6ghWkbkGNtAJpQ/pA0rM2LsnGB/WkwBH/fE1SiG+yXvx67j/uvjCS\n" +
                "hDteu5rhxI9tDCSQt+OBddYMjF5nlA+EYh9CdKEX9mzZRkRhZk+bEcUSSpjWfEmv\n" +
                "aMSon19hxiwmy/iMAQJBALRRBJr23dEzinHzNn/vOi4tShUycBWVvwcQLzrD0OK7\n" +
                "CXnZyby2L30Kl8xZGHGeZOl2GqhgiMmBXLotctbLgdECQQDfbltu720LU2DTvCQs\n" +
                "XHCDQuVmuU9fceFpJRD/7rMxLZvCL3ZAooGQxrcjbLDz8u4ojbsTW9pxJt3xUjET\n" +
                "KLrZAkAmnkNyPPT83SEFjqVZeQ7o3OJE7+x5cvzasmirGU0fghdhdXdzZ0F8ckxY\n" +
                "g6xsiRPrvFOxRBuHrKEDbsBtqGBBAkAmNDKCJ4JXu2wFCFiPFUdPynJ7PBhsU4ad\n" +
                "ee8MM/6D3C6T55Wqu5636KKL9hvTuqgqWwGv77bMPj8Y8lrd0csRAkAzikWxR+pp\n" +
                "XsLC1dIBWKoYawvk/ErIS1x7OvylCLq3RSUcqWRRk6SipyuvaCQU1MwyCHU1xEWw\n" +
                "UFDmsk1EdrU4";

        String inputStr = "chadTest123456789";
        //byte[] data = inputStr.getBytes();

        byte[] encodedData = RSAUtil.encryptByPublicKey(inputStr, publicKey);
        String temp = Base64.encodeBase64String(encodedData);
        System.out.println(temp);
        byte[] decodedData = RSAUtil
                .decryptByPrivateKey(temp,
                        privateKey);
        String outputStr = new String(decodedData);
        System.err.println("加密前: " + inputStr + "\n\r" + "解密后: " + outputStr);

        System.err.println("私钥签名——公钥验证签名");
        // 产生签名
        String sign = RSAUtil.sign(encodedData, privateKey);
        System.err.println("签名:" + sign);
        // 验证签名
        boolean status = RSAUtil.verify(encodedData, publicKey, sign);
        System.err.println("状态:" + status);

    }

}
