package com.lzw.security.common;

import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * 密码加密
 * 小程序登录抛弃密码不使用加密
 * @author James
 */
public class NoPasswordEncoder implements PasswordEncoder {
    @Override
    public String encode(CharSequence charSequence) {
        return "";
    }

    @Override
    public boolean matches(CharSequence charSequence, String s) {
        return true;
    }
}
