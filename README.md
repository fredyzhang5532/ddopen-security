## 数据加解密及签名验签工具 

### 面向开发者开源

 - 开源地址：https://github.com/larry0592/ddopen-security.git


### 使用说明详见 TestMe.java
 
```
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
```
