package com.lzw.security.common;

public enum ServiceError {

    NORMAL(1, "操作成功"),
    UN_KNOW_ERROR(-1, "未知错误"),

    /** Global Error */
    GLOBAL_ERR_NO_SIGN_IN(-10001,"未登录或登录过期/Not sign in"),
    GLOBAL_ERR_NO_CODE(-10002,"code错误/error code"),
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
