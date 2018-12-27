package com.zkteco.ddopen.security.aes;

import java.security.MessageDigest;
import java.util.Arrays;

/**
 * 计算消息签名接口
 *
 * @author Larry.lv
 * @since 1.0.0
 * Create Date 2018-10-15 17:10
 * Copyright © 1985-2018 ZKTeco Inc.All right reserved.
 **/
public class SHA1 {
    /**
     * 用SHA1算法生成安全签名
     * @param token 票据
     * @param timestamp 时间戳
     * @param nonce 随机字符串
     * @param encrypt 密文
     * @return 安全签名
     * @throws AESException
     */
    public static String getSHA1(String token, String timestamp, String nonce, String encrypt) throws AESException
    {
        try {
            String[] array = new String[] { token, timestamp, nonce, encrypt };
            StringBuffer sb = new StringBuffer();
            // 字符串排序
            Arrays.sort(array);
            for (int i = 0; i < 4; i++) {
                sb.append(array[i]);
            }
            String str = sb.toString();
            // SHA1签名生成
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(str.getBytes());
            byte[] digest = md.digest();

            StringBuffer hexstr = new StringBuffer();
            String shaHex = "";
            for (int i = 0; i < digest.length; i++) {
                shaHex = Integer.toHexString(digest[i] & 0xFF);
                if (shaHex.length() < 2) {
                    hexstr.append(0);
                }
                hexstr.append(shaHex);
            }
            return hexstr.toString();
        } catch (Exception e) {
            e.printStackTrace();
            throw new AESException(AESException.ComputeSignatureError);
        }
    }

    /**
     * 用SHA1算法生成安全签名
     * @param data
     * @return 安全签名
     * @throws AESException
     */
    public static String getSHA1(String data) throws AESException
    {
        try {
            // SHA1签名生成
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(data.getBytes());
            byte[] digest = md.digest();
            StringBuffer hexstr = new StringBuffer();
            String shaHex = "";
            for (int i = 0; i < digest.length; i++) {
                shaHex = Integer.toHexString(digest[i] & 0xFF);
                if (shaHex.length() < 2) {
                    hexstr.append(0);
                }
                hexstr.append(shaHex);
            }
            return hexstr.toString();
        } catch (Exception e) {
            throw new AESException(AESException.ComputeSignatureError);
        }
    }
}

