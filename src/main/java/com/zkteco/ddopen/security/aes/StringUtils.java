package com.zkteco.ddopen.security.aes;

import java.util.Random;

/**
 * @author Larry.lv
 * @since 1.0.0
 * Create Date 2018-10-15 18:00
 * Copyright © 1985-2018 ZKTeco Inc.All right reserved.
 **/
public class StringUtils {

    // 随机生成16位字符串
    public static String getRandomStr(int length) {
        String base = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        Random random = new Random();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < length; i++) {
            int number = random.nextInt(base.length());
            sb.append(base.charAt(number));
        }
        return sb.toString();
    }
}