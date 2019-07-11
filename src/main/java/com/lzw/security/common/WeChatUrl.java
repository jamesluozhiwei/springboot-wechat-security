package com.lzw.security.common;

public enum WeChatUrl {

    JS_CODE_2_SESSION("https://api.weixin.qq.com/sns/jscode2session")
    ,GET_ACCESS_TOKEN("https://api.weixin.qq.com/cgi-bin/token")
    ,SEND_TEMPLATE_MESSAGE("https://api.weixin.qq.com/cgi-bin/message/wxopen/template/send")
    ;

    private String url;

    WeChatUrl() {
    }

    WeChatUrl(String url) {
        this.url = url;
    }

    public String getUrl() {
        return url;
    }

    public WeChatUrl setUrl(String url) {
        this.url = url;
        return this;
    }
}
