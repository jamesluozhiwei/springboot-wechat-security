package com.lzw.security.common;

/**
 * 业务移除枚举
 * @author James
 */
public enum ServiceError {

    /**
     * 操作成功
     */
    NORMAL(1, "操作成功"),
    /**
     * 未知错误
     */
    UN_KNOW_ERROR(-1, "未知错误"),


    /**
     * 未登录或登录过期
     */
    GLOBAL_ERR_NO_SIGN_IN(-10001,"未登录或登录过期/Not sign in"),
    /**
     * 小程序登录code错误
     */
    GLOBAL_ERR_NO_CODE(-10002,"小程序登录code错误/error code"),
    /**
     * 没有操作权限
     */
    GLOBAL_ERR_NO_AUTHORITY(-10003, "没有操作权限/No operating rights"),


    ;


    private int code;
    private String msg;

    private ServiceError(int code, String msg)
    {
        this.code=code;
        this.msg=msg;
    }

    public int getCode() {
        return code;
    }

    public String getMsg() {
        return msg;
    }
}
