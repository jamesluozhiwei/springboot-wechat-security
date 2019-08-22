package com.lzw.security.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.HashSet;
import java.util.Set;

/**
 * 鉴权处理
 * @author James
 */
@Component("rbacAuthorityService")
public class RbacAuthorityService {
    /**
     * 自定义鉴权
     * @param request request
     * @param authentication    用户权限信息
     * @return                  通过返回true 不通过则返回false（所有鉴权只要有一个通过了则为通过）
     */
    public boolean hasPermission(HttpServletRequest request, Authentication authentication) {
        Object userInfo = authentication.getPrincipal();

        boolean hasPermission  = false;

        if (userInfo instanceof UserDetails) {

            String username = ((UserDetails) userInfo).getUsername();

            //获取资源
            Set<String> urls = new HashSet<>();
            // 这些 url 都是要登录后才能访问，且其他的 url 都不能访问！
            // 模拟鉴权(可根据自己的业务扩展)
            urls.add("/demo/**");
            Set set2 = new HashSet();
            Set set3 = new HashSet();

            AntPathMatcher antPathMatcher = new AntPathMatcher();

            for (String url : urls) {
                if (antPathMatcher.match(url, request.getRequestURI())) {
                    hasPermission = true;
                    break;
                }
            }
            return hasPermission;
        } else {
            return false;
        }
    }
}