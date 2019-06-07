package com.chad.crypto;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class RSAUtil {
    public static final String KEY_ALGORITHM = "RSA";
    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";
    private static final String PUBLIC_KEY = "RSAPublicKey";
    private static final String PRIVATE_KEY = "RSAPrivateKey";

    public static byte[] decryptBASE64(String key) {
        return Base64.decodeBase64(key);
    }
    public static String encryptBASE64(byte[] bytes) {
        return Base64.encodeBase64String(bytes);
    }
    /**
     * 用私鑰對資訊生成數字簽名
     *
     * [@param](https://my.oschina.net/u/2303379) data
     *            加密資料
     * [@param](https://my.oschina.net/u/2303379) privateKey
     *            私鑰
     * [@return](https://my.oschina.net/u/556800)
     * [@throws](https://my.oschina.net/throws) Exception
     */
    public static String sign(byte[] data, String privateKey) throws Exception {
// 解密由base64編碼的私鑰
        byte[] keyBytes = decryptBASE64(privateKey);
// 構造PKCS8EncodedKeySpec物件
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
// KEY_ALGORITHM 指定的加密演算法
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
// 取私鑰匙物件
        PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);
// 用私鑰對資訊生成數字簽名
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(priKey);
        signature.update(data);
        return encryptBASE64(signature.sign());
    }
    /**
     * 校驗數字簽名
     *
     * [@param](https://my.oschina.net/u/2303379) data
     *            加密資料
     * @param publicKey
     *            公鑰
     * @param sign
     *            數字簽名
     * @return 校驗成功返回true 失敗返回false
     * @throws Exception
     */
    public static boolean verify(byte[] data, String publicKey, String sign)
            throws Exception {
// 解密由base64編碼的公鑰
        byte[] keyBytes = decryptBASE64(publicKey);
// 構造X509EncodedKeySpec物件
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
// KEY_ALGORITHM 指定的加密演算法
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
// 取公鑰匙物件
        PublicKey pubKey = keyFactory.generatePublic(keySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(pubKey);
        signature.update(data);
// 驗證簽名是否正常
        return signature.verify(decryptBASE64(sign));
    }
    public static byte[] decryptByPrivateKey(byte[] data, String key)
            throws Exception {
// 對金鑰解密
        byte[] keyBytes = decryptBASE64(key);
// 取得私鑰
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
// 對資料解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }
    /**
     * 解密<br>
     * 用私鑰解密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(String data, String key)
            throws Exception {
        return decryptByPrivateKey(decryptBASE64(data), key);
    }
    /**
     * 解密<br>
     * 用公鑰解密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPublicKey(byte[] data, String key)
            throws Exception {
// 對金鑰解密
        byte[] keyBytes = decryptBASE64(key);
// 取得公鑰
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);
// 對資料解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }
    /**
     * 加密<br>
     * 用公鑰加密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(String data, String key)
            throws Exception {
// 對公鑰解密
        byte[] keyBytes = decryptBASE64(key);
// 取得公鑰
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);
// 對資料加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data.getBytes());
    }
    /**
     * 加密<br>
     * 用私鑰加密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPrivateKey(byte[] data, String key)
            throws Exception {
// 對金鑰解密
        byte[] keyBytes = decryptBASE64(key);
// 取得私鑰
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
// 對資料加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }
    /**
     * 取得私鑰
     *
     * @param keyMap
     * @return
     * @throws Exception
     */
    public static String getPrivateKey(Map<String, Key> keyMap)
            throws Exception {
        Key key = (Key) keyMap.get(PRIVATE_KEY);
        return encryptBASE64(key.getEncoded());
    }
    /**
     * 取得公鑰
     *
     * @param keyMap
     * @return
     * @throws Exception
     */
    public static String getPublicKey(Map<String, Key> keyMap) throws Exception {
        Key key = keyMap.get(PUBLIC_KEY);
        return encryptBASE64(key.getEncoded());
    }
    /**
     * 初始化金鑰
     *
     * @return
     * @throws Exception
     */
    public static Map<String, Key> initKey() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator
                .getInstance(KEY_ALGORITHM);
        keyPairGen.initialize(1024);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        Map<String, Key> keyMap = new HashMap(2);
        keyMap.put(PUBLIC_KEY, keyPair.getPublic());// 公鑰
        keyMap.put(PRIVATE_KEY, keyPair.getPrivate());// 私鑰
        return keyMap;
    }
}
