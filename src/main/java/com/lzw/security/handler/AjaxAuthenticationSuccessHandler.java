package com.lzw.security.handler;

import com.alibaba.fastjson.JSON;
import com.lzw.security.common.GenericResponse;
import com.lzw.security.common.ServiceError;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 用户登录成功时返回给前端的数据
 * 场景：当使用spring security的登录时，会触发onAuthenticationSuccess
 * @author jamesluozhiwei
 */
@Component
@Slf4j
public class AjaxAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        //自定义login，不走这里、若使用security的formLogin则自己添加业务实现(生成token、存储token等等)
        response.getWriter().write(JSON.toJSONString(GenericResponse.response(ServiceError.NORMAL)));
    }
}