package com.zkteco.ddopen.security.aes;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.util.Arrays;
import org.apache.commons.codec.binary.Base64;
import java.util.Random;

/**
 * @author Larry.lv
 * @since 1.0.0
 * Create Date 2018-10-15 17:11
 * Copyright © 1985-2018 ZKTeco Inc.All right reserved.
 **/
public class MsgCrypt {

    private static Charset CHARSET = Charset.forName("utf-8");
    Base64 base64 = new Base64();
    byte[] aesKey;
    String token;
    String appKey;

    /**
     * 构造函数
     * @param token ZKTeco设备开放平台后台，开发者设置的token
     * @param encodingAesKey ZKTeco设备开放平台后台，开发者设置的EncodingAESKey
     * @param appKey 开发者appKey
     *
     * @throws AESException 执行失败，请查看该异常的错误码和具体的错误信息
     */
    public MsgCrypt(String token, String encodingAesKey, String appKey) throws AESException {
        if (encodingAesKey.length() != 43) {
            throw new AESException(AESException.IllegalAesKey);
        }

        this.token = token;
        this.appKey = appKey;
        aesKey = Base64.decodeBase64(encodingAesKey + "=");

    }

    // 生成4个字节的网络字节序
    private byte[] getNetworkBytesOrder(int sourceNumber) {
        byte[] orderBytes = new byte[4];
        orderBytes[3] = (byte) (sourceNumber & 0xFF);
        orderBytes[2] = (byte) (sourceNumber >> 8 & 0xFF);
        orderBytes[1] = (byte) (sourceNumber >> 16 & 0xFF);
        orderBytes[0] = (byte) (sourceNumber >> 24 & 0xFF);
        return orderBytes;
    }

    // 还原4个字节的网络字节序
    private int recoverNetworkBytesOrder(byte[] orderBytes) {
        int sourceNumber = 0;
        for (int i = 0; i < 4; i++) {
            sourceNumber <<= 8;
            sourceNumber |= orderBytes[i] & 0xff;
        }
        return sourceNumber;
    }

    // 随机生成16位字符串
    public String getRandomStr() {
        String base = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        Random random = new Random();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < 16; i++) {
            int number = random.nextInt(base.length());
            sb.append(base.charAt(number));
        }
        return sb.toString();
    }

    /**
     * 对明文进行加密.
     *
     * @param text 需要加密的明文
     * @return 加密后base64编码的字符串
     * @throws AESException aes加密失败
     */
   public String encrypt(String randomStr, String text) throws AESException {
        ByteGroup byteCollector = new ByteGroup();
        byte[] randomStrBytes = randomStr.getBytes(CHARSET);
        byte[] textBytes = text.getBytes(CHARSET);
        byte[] networkBytesOrder = getNetworkBytesOrder(textBytes.length);
        byte[] corpidBytes = appKey.getBytes(CHARSET);

        // randomStr + networkBytesOrder + text + corpid
        byteCollector.addBytes(randomStrBytes);
        byteCollector.addBytes(networkBytesOrder);
        byteCollector.addBytes(textBytes);
        byteCollector.addBytes(corpidBytes);

        // ... + pad: 使用自定义的填充方式对明文进行补位填充
        byte[] padBytes = PKCS7Encoder.encode(byteCollector.size());
        byteCollector.addBytes(padBytes);

        // 获得最终的字节流, 未加密
        byte[] unencrypted = byteCollector.toBytes();
        try {
            // 设置加密模式为AES的CBC模式
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
            IvParameterSpec iv = new IvParameterSpec(aesKey, 0, 16);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);

            // 加密
            byte[] encrypted = cipher.doFinal(unencrypted);

            // 使用BASE64对加密后的字符串进行编码
            String base64Encrypted = base64.encodeToString(encrypted);

            return base64Encrypted;
        } catch (Exception e) {
            e.printStackTrace();
            throw new AESException(AESException.EncryptAESError);
        }
    }

    /**
     * 对密文进行解密.
     *
     * @param text 需要解密的密文
     * @return 解密得到的明文
     * @throws AESException aes解密失败
     */
   public String decrypt(String text) throws AESException {
        byte[] original;
        try {
            // 设置解密模式为AES的CBC模式
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec key_spec = new SecretKeySpec(aesKey, "AES");
            IvParameterSpec iv = new IvParameterSpec(Arrays.copyOfRange(aesKey, 0, 16));
            cipher.init(Cipher.DECRYPT_MODE, key_spec, iv);

            // 使用BASE64对密文进行解码
            byte[] encrypted = Base64.decodeBase64(text);
            // 解密
            original = cipher.doFinal(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            throw new AESException(AESException.DecryptAESError);
        }

        String xmlContent, from_appKey;
        try {
            // 去除补位字符
            byte[] bytes = PKCS7Encoder.decode(original);

            // 分离16位随机字符串,网络字节序和corpId
            byte[] networkOrder = Arrays.copyOfRange(bytes, 16, 20);

            int xmlLength = recoverNetworkBytesOrder(networkOrder);

            xmlContent = new String(Arrays.copyOfRange(bytes, 20, 20 + xmlLength), CHARSET);
            from_appKey = new String(Arrays.copyOfRange(bytes, 20 + xmlLength, bytes.length), CHARSET);
        } catch (Exception e) {
            e.printStackTrace();
            throw new AESException(AESException.IllegalBuffer);
        }

        //appKey不相同的情况
        if (!from_appKey.equals(appKey)) {
            throw new AESException(AESException.ValidateCorpidError);
        }
        return xmlContent;

    }

    /**
     * 将消息加密.
     * <ol>
     * 	<li>对要发送的消息进行AES-CBC加密</li>
     * </ol>
     *
     * @param replyMsg 
     *
     * @return 加密后的可以直接回复的密文
     * @throws AESException 执行失败，请查看该异常的错误码和具体的错误信息
     */
    public String encryptMsg(String replyMsg) throws AESException {
        // 加密
        String encrypt = encrypt(getRandomStr(), replyMsg);
        return encrypt;
    }

    /**
     * 检验消息的真实性，并且获取解密后的明文.
     * <ol>
     * 	<li>利用收到的密文生成安全签名，进行签名验证</li>
     * 	<li>对消息进行解密</li>
     * </ol>
     *
     * @param msgSignature 签名串，对应URL参数的msg_signature
     * @param timeStamp 时间戳，对应URL参数的timestamp
     * @param nonce 随机串，对应URL参数的nonce
     * @param encrypt  密文，对应POST请求的数据
     *
     * @return 解密后的原文
     * @throws AESException 执行失败，请查看该异常的错误码和具体的错误信息
     */
    public String decryptMsg(String msgSignature, String timeStamp, String nonce, String encrypt)
            throws AESException {

        // 验证安全签名
        String signature = SHA1.getSHA1(token, timeStamp, nonce, encrypt);

        // 和URL中的签名比较是否相等
        if (!signature.equals(msgSignature)) {
            throw new AESException(AESException.ValidateSignatureError);
        }
        // 解密
        String result = decrypt(encrypt);
        return result;
    }

    /**
     * 验证URL
     * @param msgSignature 签名串，对应URL参数的msg_signature
     * @param timeStamp 时间戳，对应URL参数的timestamp
     * @param nonce 随机串，对应URL参数的nonce
     * @param echoStr 随机串，对应URL参数的echostr
     *
     * @return 解密之后的echostr
     * @throws AESException 执行失败，请查看该异常的错误码和具体的错误信息
     */
    public String VerifyURL(String msgSignature, String timeStamp, String nonce, String echoStr)
            throws AESException {
        String signature = SHA1.getSHA1(token, timeStamp, nonce, echoStr);
        if (!signature.equals(msgSignature)) {
            throw new AESException(AESException.ValidateSignatureError);
        }
        String result = decrypt(echoStr);
        return result;
    }

}
