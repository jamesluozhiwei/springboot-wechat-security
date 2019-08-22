package com.lzw.security.service;
import com.lzw.security.entity.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

/**
 * 用户认证、权限、使用security的表单登录时会被调用(自定义登录请忽略)
 * @author jamesluozhiwei
 */
@Component
@Slf4j
public class SelfUserDetailsServiceImpl implements UserDetailsService {


    /**
     * 若使用security表单鉴权则需实现该方法，通过username获取用户信息（密码、权限等等）
     * @param username 用户名
     * @return  用户信息
     * @throws UsernameNotFoundException 用户未找到移除
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        //通过username查询用户
        //根据自己的业务获取用户信息
        //模拟从数据库获取到用户信息
        User user = new User();
        if(user == null){
            //仍需要细化处理
            throw new UsernameNotFoundException("该用户不存在");
        }

        Set<SimpleGrantedAuthority> authoritiesSet = new HashSet<>();
        // 模拟从数据库中获取用户权限
        authoritiesSet.add(new SimpleGrantedAuthority("test:list"));
        authoritiesSet.add(new SimpleGrantedAuthority("test:add"));
        user.setAuthorities(authoritiesSet);

        log.info("用户{}验证通过",username);
        return user;
    }
}
