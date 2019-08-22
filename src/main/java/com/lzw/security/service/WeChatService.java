package com.lzw.security.service;

import com.lzw.security.common.GenericResponse;

/**
 * 微信业务接口
 */
public interface WeChatService {

    /**
     * 小程序登录
     * @param code 小程序登录 code
     * @return 业务结果
     */
    GenericResponse wxLogin(String code);

}
