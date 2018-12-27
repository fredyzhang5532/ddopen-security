package com.zkteco.ddopen.security.aes;

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import com.alibaba.fastjson.JSONObject;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Calendar;

/**
 * 单元测试
 * @author Larry.lv
 * @since 1.0.0
 * Create Date 2018-10-15 17:47
 * Copyright © 1985-2018 ZKTeco Inc.All right reserved.
 **/
public class TestMe {

    @Test
    public void testCheckURL(){
        String sToken = "LyENVdO33JcTxW";
        String sAppKey = "ww9c85c32b3dce1697";
        String sEncodingAESKey = "WiAqCmVluX9DHg7s7NloiQMW6imtx6BWt8ywhoyei12";
        String dChoStr = StringUtils.getRandomStr(16);
        try {
            MsgCrypt msgCrypt = new MsgCrypt(sToken,sEncodingAESKey,sAppKey);
            //加密Echo随机数
            String eChoStr = msgCrypt.encryptMsg(dChoStr);
            System.out.println("加密Echo随机数:"+eChoStr);
            //时间戳
            String timeStamp = String.valueOf(System.currentTimeMillis());
            System.out.println("时间戳:"+timeStamp);
            //生成随机数
            String nonce = StringUtils.getRandomStr(8);
            System.out.println("生成随机数:"+nonce);
            //生成签名
            String signature = SHA1.getSHA1(sToken, timeStamp, nonce, eChoStr);
            System.out.println("生成签名:"+signature);
            //解密eChoStr
            String result = msgCrypt.VerifyURL(signature,timeStamp, nonce, eChoStr);
            System.out.println("解密eChoStr:"+result);
            //校验result、dChoStr
            assertEquals(result, dChoStr);
        } catch (AESException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testDecryptAndSignMsg(){
        String sToken = "LyENVdO33JcTxW";
        String sAppKey = "ww9c85c32b3dce1697";
        String sEncodingAESKey = "WiAqCmVluX9DHg7s7NloiQMW6imtx6BWt8ywhoyeiav";
        try {
            //请求方 Send
            MsgCrypt msgCrypt = new MsgCrypt(sToken,sEncodingAESKey,sAppKey);
            //时间戳
            String timeStamp = String.valueOf(System.currentTimeMillis());
            //生成随机数
            String nonce = StringUtils.getRandomStr(8);
            JSONObject  jsonObject = new JSONObject();
            jsonObject.put("sid","att.ems.transaction.upload");
            jsonObject.put("sn","10283012035");
            String jsonString = jsonObject.toJSONString();
            //原始业务请求包体加密
            String encryptJsonString = msgCrypt.encryptMsg(jsonString);
            //封装业务请求包体加密
            String reqData = "{ \"sys\":\"ww9c85c32b3dce1697\",\"data\":\""+encryptJsonString+"\"}";
            //生成签名
            String sourceSignature = SHA1.getSHA1(sToken, timeStamp, nonce, encryptJsonString);


            //接收方 Receive
            JSONObject requestBody = JSONObject.parseObject(reqData);
            String encrypt = requestBody.getString("data");

            String targetSignature  = SHA1.getSHA1(sToken, timeStamp, nonce, encrypt);
            assertEquals(sourceSignature, targetSignature);


            String decryptMsg = msgCrypt.decryptMsg(targetSignature,timeStamp,nonce,encrypt);
            assertEquals(decryptMsg, jsonString);
        }
        catch (AESException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testDynamicQRcode(){
        //设备SN
        String sn = "3389153100001";
        //时间戳
        Calendar cal = Calendar.getInstance();
        String timestamp =  String.valueOf(cal.getTimeInMillis() / 1000);

        //生成随机数
        String nonce = "17394011";
        //type
        String type = "qrcode";
        //SecretNo
        String SecretNo = "ed712d95cee095898c7838c57e99a403";

        String[] array = new String[] { sn, SecretNo,timestamp, nonce, type};
        StringBuffer sb = new StringBuffer();
        // 字符串排序
        Arrays.sort(array);
        for (int i = 0; i < array.length; i++) {
            sb.append(array[i]);
        }
        String str = sb.toString();
        String url = "https://open.work.weixin.qq.com/connect/hardware?sn=%s&timestamp=%s&nonce=%s&signature=%s&type=qrcode";
        try {
            String signature = SHA1.getSHA1(str);
            url = String.format(url,sn,timestamp,nonce,signature);
            System.out.println("DynamicQRcode URL:"+url);
        } catch (AESException e) {
            e.printStackTrace();
            return;
        }
    }




    /**
     *
     * @param plainText
     *            明文
     * @return 32位密文
     */
    public String encryption(String plainText) {
        String re_md5 = new String();
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(plainText.getBytes());
            byte b[] = md.digest();
            int i;
            StringBuffer buf = new StringBuffer("");
            for (int offset = 0; offset < b.length; offset++) {
                i = b[offset];
                if (i < 0)
                    i += 256;
                if (i < 16)
                    buf.append("0");
                buf.append(Integer.toHexString(i));
            }

            re_md5 = buf.toString();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return re_md5;
    }
}
