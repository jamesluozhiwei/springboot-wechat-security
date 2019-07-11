package com.lzw.security.util;

import com.alibaba.fastjson.JSONObject;
import com.lzw.security.common.WeChatUrl;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.codehaus.xfire.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.AlgorithmParameters;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Slf4j
public class Jcode2SessionUtil {

    /**
     * 请求微信后台获取用户数据
     * @param code wx.login获取到的临时code
     * @return 请求结果
     * @throws Exception
     */
    public static String jscode2session(String appid,String secret,String code,String grantType)throws Exception{
        //定义返回的json对象
        JSONObject result = new JSONObject();
        //创建请求通过code换取session等数据
        HttpPost httpPost = new HttpPost(WeChatUrl.JS_CODE_2_SESSION.getUrl());
        List<NameValuePair> params=new ArrayList<NameValuePair>();
        //建立一个NameValuePair数组，用于存储欲传送的参数
        params.add(new BasicNameValuePair("appid",appid));
        params.add(new BasicNameValuePair("secret",secret));
        params.add(new BasicNameValuePair("js_code",code));
        params.add(new BasicNameValuePair("grant_type",grantType));
        //设置编码
        httpPost.setEntity(new UrlEncodedFormEntity(params));//添加参数
        return EntityUtils.toString(new DefaultHttpClient().execute(httpPost).getEntity());
    }
    /**
     * 解密用户敏感数据获取用户信息
     * @param sessionKey 数据进行加密签名的密钥
     * @param encryptedData 包括敏感数据在内的完整用户信息的加密数据
     * @param iv 加密算法的初始向量
     * @return
     */
    public static String getUserInfo(String encryptedData,String sessionKey,String iv)throws Exception{
        // 被加密的数据
        byte[] dataByte = Base64.decode(encryptedData);
        // 加密秘钥
        byte[] keyByte = Base64.decode(sessionKey);
        // 偏移量
        byte[] ivByte = Base64.decode(iv);
        // 如果密钥不足16位，那么就补足.  这个if 中的内容很重要
        int base = 16;
        if (keyByte.length % base != 0) {
            int groups = keyByte.length / base + (keyByte.length % base != 0 ? 1 : 0);
            byte[] temp = new byte[groups * base];
            Arrays.fill(temp, (byte) 0);
            System.arraycopy(keyByte, 0, temp, 0, keyByte.length);
            keyByte = temp;
        }
        // 初始化
        Security.addProvider(new BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding","BC");
        SecretKeySpec spec = new SecretKeySpec(keyByte, "AES");
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("AES");
        parameters.init(new IvParameterSpec(ivByte));
        cipher.init(Cipher.DECRYPT_MODE, spec, parameters);// 初始化
        byte[] resultByte = cipher.doFinal(dataByte);
        if (null != resultByte && resultByte.length > 0) {
            String result = new String(resultByte, "UTF-8");
            log.info(result);
            return result;
        }
        return null;
    }

    /**
     * 获取微信接口调用凭证
     * @param appid
     * @param secret
     * @return 返回String 可转JSON
     */
    public static String getAccessToken(String appid,String secret){
        JSONObject params = new JSONObject();
        params.put("grant_type","client_credential");//获取接口调用凭证
        params.put("appid",appid);
        params.put("secret",secret);
        return HttpUtil.sendGet(WeChatUrl.GET_ACCESS_TOKEN.getUrl()+"?grant_type=client_credential&appid=" + appid + "&secret=" + secret);
    }

    /**
     * 发送模板消息
     * @param access_token      接口调用凭证
     * @param touser            接收者（用户）的 openid
     * @param template_id       所需下发的模板消息id
     * @param page              点击模版卡片后跳转的页面，仅限本小程序内的页面。支持带参数，（eg：index?foo=bar）。该字段不填则模版无法跳转
     * @param form_id           表单提交场景下，为submit事件带上的formId；支付场景下，为本次支付的 prepay_id
     * @param data              模版内容，不填则下发空模版。具体格式请参照官网示例
     * @param emphasis_keyword  模版需要放大的关键词，不填则默认无放大
     * @return                  返回String可转JSON
     */
    public static String sendTemplateMessage(String access_token,String touser,String template_id,String page,String form_id,Object data,String emphasis_keyword){
        JSONObject params = new JSONObject();
        params.put("touser",touser);
        params.put("template_id",template_id);
        if (null != page && !"".equals(page)){
            params.put("page",page);
        }
        params.put("form_id",form_id);
        params.put("data",data);
        if (null != emphasis_keyword && !"".equals(emphasis_keyword)){
            params.put("emphasis_keyword",emphasis_keyword);
        }
        //发送请求
        return HttpUtil.sendPost(WeChatUrl.SEND_TEMPLATE_MESSAGE.getUrl() + "?access_token=" + access_token,params.toString());
    }

}
