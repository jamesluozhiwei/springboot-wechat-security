# security
springboot+security+jwt+redis 实现微信小程序登录及token权限鉴定
tips:这是实战篇，默认各位看官具备相应的基础(文中使用了Lombok插件，如果使用源码请先安装插件)

@[TOC]
# 项目配置
## 依赖
```xml
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-redis</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.mybatis.spring.boot</groupId>
            <artifactId>mybatis-spring-boot-starter</artifactId>
            <version>2.0.1</version>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-devtools</artifactId>
            <scope>runtime</scope>
            <optional>true</optional>
        </dependency>
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>
        <!--JWT-->
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt</artifactId>
            <version>0.9.0</version>
        </dependency>
        <!-- fastjson -->
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>fastjson</artifactId>
            <version>1.2.36</version>
        </dependency>
        <!-- druid数据库连接池 -->
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>druid</artifactId>
            <version>1.1.8</version>
        </dependency>
        <!-- https://mvnrepository.com/artifact/log4j/log4j -->
        <dependency>
            <groupId>log4j</groupId>
            <artifactId>log4j</artifactId>
            <version>1.2.17</version>
        </dependency>
        <!-- http请求所需jar包 -->
        <!-- https://mvnrepository.com/artifact/org.apache.httpcomponents/httpcore -->
        <dependency>
            <groupId>org.apache.httpcomponents</groupId>
            <artifactId>httpcore</artifactId>
            <version>4.4.11</version>
        </dependency>
        <!-- https://mvnrepository.com/artifact/org.apache.httpcomponents/httpclient -->
        <dependency>
            <groupId>org.apache.httpcomponents</groupId>
            <artifactId>httpclient</artifactId>
            <version>4.5.7</version>
        </dependency>
        <!-- Jcode2Session解密所需jar包 -->
        <!-- https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15 -->
        <dependency>
            <groupId>org.bouncycastle</groupId>
            <artifactId>bcprov-jdk15</artifactId>
            <version>1.46</version>
        </dependency>
        <!-- 注意导入xfire-all jar包会与spring冲突 -->
        <dependency>
            <groupId>org.codehaus.xfire</groupId>
            <artifactId>xfire-all</artifactId>
            <version>1.2.6</version>
            <exclusions>
                <exclusion>
                    <groupId>org.springframework</groupId>
                    <artifactId>spring</artifactId>
                </exclusion>
            </exclusions>
        </dependency>
```
## application.yml
```yml
spring:
  datasource:
    username: root
    password: 123456
    url: jdbc:mysql://localhost:3306/db_XXX?characterEncoding=utf-8&useSSl=false
    driver-class-name: com.mysql.jdbc.Driver
    # 此处使用Druid数据库连接池
    type: com.alibaba.druid.pool.DruidDataSource
    #监控统计拦截的filters
    filters: stat,wall,log4j
    #druid配置
    #配置初始化大小/最小/最大
    initialSize: 5
    minIdle: 5
    maxActive: 20
    #获取连接等待超时时间
    maxWait: 60000
    #间隔多久进行一次检测，检测需要关闭的空闲连接
    timeBetweenEvictionRunsMillis: 60000
    #一个连接在池中最小生存的时间
    minEvictableIdleTimeMillis: 300000
    validationQuery: SELECT 1 FROM DUAL
    testWhileIdle: true
    testOnBorrow: false
    testOnReturn: false
    #打开PSCache，并指定每个连接上PSCache的大小。oracle设为true，mysql设为false。分库分表较多推荐设置为false
    poolPreparedStatements: false
    maxPoolPreparedStatementPerConnectionSize: 20
    # 通过connectProperties属性来打开mergeSql功能；慢SQL记录
    connectionProperties:
      druid:
        stat:
          mergeSql: true
          slowSqlMillis: 5000
  http:
    encoding:
      charset: utf-8
      force: true
      enabled: true
  redis:
    host: 127.0.0.1
    port: 6379
    password: 123456


#mybatis是独立节点，需要单独配置
mybatis:
  mapper-locations: classpath*:mapper/*.xml
  type-aliases-package: com.lzw.security.entity
  configuration:
    map-underscore-to-camel-case: true

server:
  port: 8080
  tomcat:
    uri-encoding: utf-8
  servlet:
    context-path: /

#自定义参数，可以迁移走
token:
  #redis默认过期时间（2小时）(这是自定义的)(毫秒)
  expirationMilliSeconds: 7200000

#微信相关参数
weChat:
  #小程序appid
  appid: aaaaaaaaaaaaaaaa
  #小程序密钥
  secret: ssssssssssssssss
```

# 程序代码
## security相关

### security核心配置类

```java
import com.lzw.security.common.NoPasswordEncoder;
import com.lzw.security.filter.JwtAuthenticationTokenFilter;
import com.lzw.security.handler.*;
import com.lzw.security.service.SelfUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * @author: jamesluozhiwei
 * @description: security核心配置类
 */
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)//表示开启全局方法注解，可在指定方法上面添加注解指定权限，需含有指定权限才可调用(基于表达式的权限控制)
public class SpringSecurityConf extends WebSecurityConfigurerAdapter {


    @Autowired
    AjaxAuthenticationEntryPoint authenticationEntryPoint;//未登陆时返回 JSON 格式的数据给前端（否则为 html）

    @Autowired
    AjaxAuthenticationSuccessHandler authenticationSuccessHandler; //登录成功返回的 JSON 格式数据给前端（否则为 html）

    @Autowired
    AjaxAuthenticationFailureHandler authenticationFailureHandler; //登录失败返回的 JSON 格式数据给前端（否则为 html）

    @Autowired
    AjaxLogoutSuccessHandler logoutSuccessHandler;//注销成功返回的 JSON 格式数据给前端（否则为 登录时的 html）

    @Autowired
    AjaxAccessDeniedHandler accessDeniedHandler;//无权访问返回的 JSON 格式数据给前端（否则为 403 html 页面）

    @Autowired
    SelfUserDetailsService userDetailsService; // 自定义user

    @Autowired
    JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter; // JWT 拦截器

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 加入自定义的安全认证
        //auth.authenticationProvider(provider);
        auth.userDetailsService(userDetailsService).passwordEncoder(new NoPasswordEncoder());//这里使用自定义的加密方式(不使用加密)，security提供了 BCryptPasswordEncoder 加密可自定义或使用这个
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
    	// 请根据自身业务进行扩展
        // 去掉 CSRF
        http.csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //关闭session管理，使用token机制处理
                .and()

                .httpBasic().authenticationEntryPoint(authenticationEntryPoint)
                //.and().antMatcher("/login")
                //.and().authorizeRequests().anyRequest().access("@rbacauthorityservice.hasPermission(request,authentication)")// 自定义权限校验  RBAC 动态 url 认证
                .and().authorizeRequests().antMatchers(HttpMethod.GET,"/test").hasAuthority("test:list")
                .and().authorizeRequests().antMatchers(HttpMethod.POST,"/test").hasAuthority("test:add")
                .and().authorizeRequests().antMatchers(HttpMethod.PUT,"/test").hasAuthority("test:update")
                .and().authorizeRequests().antMatchers(HttpMethod.DELETE,"/test").hasAuthority("test:delete")
                .and().authorizeRequests().antMatchers("/test/*").hasAuthority("test:manager")
                .and().authorizeRequests().antMatchers("/login").permitAll() //放行login(这里使用自定义登录)
                .and().authorizeRequests().antMatchers("/hello").permitAll();//permitAll表示不需要认证
                //微信小程序登录不给予账号密码，关闭
//                .and()
                  //开启登录, 定义当需要用户登录时候，转到的登录页面、这是使用security提供的formLogin，不需要自己实现登录登出逻辑、但需要实现相关方法
//                .formLogin()  
//                .loginPage("/test/login.html")//可不指定，使用security自带的登录页面
//                .loginProcessingUrl("/login") //登录地址
//                .successHandler(authenticationSuccessHandler) // 登录成功处理
//                .failureHandler(authenticationFailureHandler) // 登录失败处理
//                .permitAll()

//                .and()
//                .logout()//默认注销行为为logout
//                .logoutUrl("/logout")
//                .logoutSuccessHandler(logoutSuccessHandler)
//                .permitAll();

        // 记住我
//        http.rememberMe().rememberMeParameter("remember-me")
//                .userDetailsService(userDetailsService).tokenValiditySeconds(1000);

        http.exceptionHandling().accessDeniedHandler(accessDeniedHandler); // 无权访问 JSON 格式的数据
        http.addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class); // JWT Filter

    }

    @Bean
    GrantedAuthorityDefaults grantedAuthorityDefaults(){
        return new GrantedAuthorityDefaults("");//remove the ROLE_ prefix
    }

}
```
注意：这里说明一下hasRole("ADMIN")和hasAuthority("ADMIN")的区别，在鉴权的时候，hasRole会给 "ADMIN" 加上 ROLE_ 变成 "ROLE_ADMIN" 而hasAuthority则不会 还是 "ADMIN"、如果不想让其添加前缀，可以使用如下代码移除

```java
	//在上面也有体现
	@Bean
    GrantedAuthorityDefaults grantedAuthorityDefaults(){
        return new GrantedAuthorityDefaults("");//remove the ROLE_ prefix
    }
```
### 鉴权各种情况处理类
上述代码引用的鉴权状态处理代码

#### 无权访问
```java
/**
 * @author: jamesluozhiwei
 * @description: 无权访问
 */
@Component
public class AjaxAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e) throws IOException, ServletException {
        response.setCharacterEncoding("utf-8");
        response.getWriter().write(JSON.toJSONString(GenericResponse.response(ServiceError.GLOBAL_ERR_NO_AUTHORITY)));
    }
}
```
#### 用户未登录时返回给前端的数据
```java
/**
 * @author: jamesluozhiwei
 * @description: 用户未登录时返回给前端的数据
 */
@Component
public class AjaxAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
        request.setCharacterEncoding("utf-8");
        response.getWriter().write(JSON.toJSONString(GenericResponse.response(ServiceError.GLOBAL_ERR_NO_SIGN_IN)));
    }
}
```
#### 用户登录失败时返回给前端的数据(本程序未使用)
适用于账号密码登录模式
```java
/**
 * @author: jamesluozhiwei
 * @description: 用户登录失败时返回给前端的数据
 */
@Component
public class AjaxAuthenticationFailureHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
        response.setCharacterEncoding("utf-8");
        response.getWriter().write(JSON.toJSONString(GenericResponse.response(ServiceError.GLOBAL_ERR_NO_CODE)));
    }

}
```
#### 用户登录成功时返回给前端的数据
适用于账号密码登录模式
```java
/**
 * @author: jamesluozhiwei
 * @description: 用户登录成功时返回给前端的数据
 */
@Component
@Slf4j
public class AjaxAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    @Autowired
    private RedisUtil redisUtil;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        //自定义login，不走这里、若使用security的formLogin则自己添加业务实现(生成token、存储token等等)
        response.getWriter().write(JSON.toJSONString(GenericResponse.response(ServiceError.NORMAL)));
    }
}
```
#### 登出成功
适用于账号密码登录模式
```java
/**
 * @author: jamesluozhiwei
 * @description: 登出成功
 */
@Component
@Slf4j
public class AjaxLogoutSuccessHandler implements LogoutSuccessHandler {

    @Autowired
    private RedisUtil redisUtil;

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        //没有logout不走这里、若使用security的formLogin则自己添加业务实现（移除token等等）
        response.getWriter().write(JSON.toJSONString(GenericResponse.response(ServiceError.NORMAL)));
    }

}
```

### JWT自定义过滤器
在security配置类中有体现,主要用于解析token，并从redis中获取用户相关权限
```java
import com.alibaba.fastjson.JSON;
import com.lzw.security.common.GenericResponse;
import com.lzw.security.common.ServiceError;
import com.lzw.security.entity.User;
import com.lzw.security.util.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Set;

/**
 * @author: jamesluozhiwei
 * @description: 确保在一次请求只通过一次filter，而不需要重复执行
 */
@Component
@Slf4j
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    @Value("${token.expirationMilliSeconds}")
    private long expirationMilliSeconds;

    @Autowired
    RedisUtil redisUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //获取header中的token信息
        String authHeader = request.getHeader("Authorization");
        response.setCharacterEncoding("utf-8");
        if (null == authHeader || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);//token格式不正确
            return;
        }
        String authToken = authHeader.substring("Bearer ".length());

        String subject = JwtTokenUtil.parseToken(authToken);//获取在token中自定义的subject，用作用户标识，用来获取用户权限

        //获取redis中的token信息

        if (!redisUtil.hasKey(authToken)){
            //token 不存在 返回错误信息
            response.getWriter().write(JSON.toJSONString(GenericResponse.response(ServiceError.GLOBAL_ERR_NO_SIGN_IN)));
            return;
        }

        //获取缓存中的信息(根据自己的业务进行拓展)
        HashMap<String,Object> hashMap = (HashMap<String, Object>) redisUtil.hget(authToken);
        //从tokenInfo中取出用户信息
        User user = new User();
        user.setId(Long.parseLong(hashMap.get("id").toString())).setAuthorities((Set<? extends GrantedAuthority>) hashMap.get("authorities"));
        if (null == hashMap){
            //用户信息不存在或转换错误，返回错误信息
            response.getWriter().write(JSON.toJSONString(GenericResponse.response(ServiceError.GLOBAL_ERR_NO_SIGN_IN)));
            return;
        }
        //更新token过期时间
        redisUtil.setKeyExpire(authToken,expirationMilliSeconds);
        //将信息交给security
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user,null,user.getAuthorities());
        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        filterChain.doFilter(request,response);
    }
}
```
### SelfUserDetailsService(基于自定义登录，token验证可忽略)
```java
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
 * @author: jamesluozhiwei
 */
@Component
@Slf4j
public class SelfUserDetailsService implements UserDetailsService {

    //@Autowired
    //private UserMapper userMapper;

    /**
     * 若使用security表单鉴权则需实现该方法，通过username获取用户信息（密码、权限等等）
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        //通过username查询用户
        //根据自己的业务获取用户信息
        //SelfUserDetails user = userMapper.getUser(username);
        //模拟从数据库获取到用户信息
        User user = new User();
        if(user == null){
            //仍需要细化处理
            throw new UsernameNotFoundException("该用户不存在");
        }

        Set authoritiesSet = new HashSet();
        // 模拟从数据库中获取用户权限
        authoritiesSet.add(new SimpleGrantedAuthority("test:list"));
        authoritiesSet.add(new SimpleGrantedAuthority("test:add"));
        user.setAuthorities(authoritiesSet);

        log.info("用户{}验证通过",username);
        return user;
    }
}
```
### 密码加密方式
这里就不用加密了
```java
import org.springframework.security.crypto.password.PasswordEncoder;

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

```
### RBAC自定义鉴权
可在security配置中，通过
```java
.and().authorizeRequests().anyRequest().access("@rbacauthorityservice.hasPermission(request,authentication)")//anyRequest表示全部
.and().authorizeRequests().antMatchers("/test/*").access("@rbacauthorityservice.hasPermission(request,authentication)")//也可以指定相应的地址
```
指定自定义鉴权方式，也可指定具体的URL
```java
/**
 * 鉴权处理
 */
@Component("rbacauthorityservice")//此处bean名称要和上述的一致
public class RbacAuthorityService {
    /**
     * 可根据业务自定义鉴权
     * @param request
     * @param authentication    用户权限信息
     * @return                  通过返回true 不通过则返回false（所有鉴权只要有一个通过了则为通过）
     */
    public boolean hasPermission(HttpServletRequest request, Authentication authentication) {
        Object userInfo = authentication.getPrincipal();

        boolean hasPermission  = false;

        if (userInfo instanceof UserDetails) {

            String username = ((UserDetails) userInfo).getUsername();

            //获取资源
            Set<String> urls = new HashSet();
            // 这些 url 都是要登录后才能访问，且其他的 url 都不能访问！
            // 模拟鉴权(可根据自己的业务扩展)
            urls.add("/demo/**");//application.yml里设置了项目路径，百度一下我就不贴了
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
```
## 微信小程序相关
### 通过code换取openid
```java
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
```
请求地址枚举,可自行扩展
```java
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
```
http工具类
```java
import com.alibaba.fastjson.JSONObject;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;
/**
 * 请求工具类
 * @author jamesluozhiwei
 */
public class HttpUtil {

    /**
     * 发送get请求
     * @param url
     * @return
     */
    public static String sendGet(String url){
        DefaultHttpClient httpClient = new DefaultHttpClient();
        HttpGet httpGet = new HttpGet(url);
        String result = null;
        try {
            HttpResponse response = httpClient.execute(httpGet);
            HttpEntity entity = response.getEntity();
            if (entity != null) {
                result = EntityUtils.toString(entity, "UTF-8");
            }
            httpGet.releaseConnection();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return result;
    }


    /**
     * 发送post请求
     * @param url
     * @param params 可使用JSONObject转JSON字符串
     * @return
     */
    public static String sendPost(String url,String params){
        DefaultHttpClient httpClient = new DefaultHttpClient();
        HttpPost httpPost = new HttpPost(url);
        JSONObject jsonObject = null;
        try {
            httpPost.setEntity(new StringEntity(params, "UTF-8"));
            HttpResponse response = httpClient.execute(httpPost);
            return EntityUtils.toString(response.getEntity(),"UTF-8");
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 发送post请求
     * @param httpUrl
     * @param param JSON字符串
     * @return
     */
    public static String doPostBase64(String httpUrl, String param) {

        HttpURLConnection connection = null;
        InputStream is = null;
        OutputStream os = null;
        BufferedReader br = null;
        String result = null;
        try {
            URL url = new URL(httpUrl);
            // 通过远程url连接对象打开连接
            connection = (HttpURLConnection) url.openConnection();
            // 设置连接请求方式
            connection.setRequestMethod("POST");
            // 设置连接主机服务器超时时间：15000毫秒
            connection.setConnectTimeout(15000);
            // 设置读取主机服务器返回数据超时时间：60000毫秒
            connection.setReadTimeout(60000);

            // 默认值为：false，当向远程服务器传送数据/写数据时，需要设置为true
            connection.setDoOutput(true);
            // 默认值为：true，当前向远程服务读取数据时，设置为true，该参数可有可无
            connection.setDoInput(true);
            // 设置传入参数的格式:请求参数应该是 name1=value1&name2=value2 的形式。
            connection.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
            // 通过连接对象获取一个输出流
            os = connection.getOutputStream();
            // 通过输出流对象将参数写出去/传输出去,它是通过字节数组写出的

            os.write(param.getBytes());

            // 通过连接对象获取一个输入流，向远程读取
            if (connection.getResponseCode() == 200) {

                is = connection.getInputStream();

                ByteArrayOutputStream swapStream = new ByteArrayOutputStream();
                byte[] buff = new byte[100];
                int rc = 0;
                while ((rc = is.read(buff, 0, 100)) > 0) {
                    swapStream.write(buff, 0, rc);
                }
                byte[] in2b = swapStream.toByteArray();
                String tmp = new String(in2b);
                if (tmp.indexOf("errcode") == -1)
                    return Base64.getEncoder().encodeToString(in2b);
                return tmp;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }  finally {
            // 关闭资源
            if (null != br) {
                try {
                    br.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (null != os) {
                try {
                    os.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (null != is) {
                try {
                    is.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            // 断开与远程地址url的连接
            connection.disconnect();
        }
        return result;
    }
}
```
### 业务层
```java
/**
 * 微信业务接口
 */
public interface WeChatService {

    /**
     * 小程序登录
     * @param code
     * @return
     */
    GenericResponse wxLogin(String code)throws Exception;

}
```
```java
import com.alibaba.fastjson.JSONObject;
import com.lzw.security.common.GenericResponse;
import com.lzw.security.common.ServiceError;
import com.lzw.security.entity.User;
import com.lzw.security.service.WeChatService;
import com.lzw.security.util.Jcode2SessionUtil;
import com.lzw.security.util.JwtTokenUtil;
import com.lzw.security.util.RedisUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

/**
 * 微信业务实现类
 */
@Service
@Slf4j
public class WeChatServiceImpl implements WeChatService {

    @Value("${weChat.appid}")
    private String appid;

    @Value("${weChat.secret}")
    private String secret;

    @Autowired
    private RedisUtil redisUtil;

    @Override
    public GenericResponse wxLogin(String code) throws Exception{
        JSONObject sessionInfo = JSONObject.parseObject(jcode2Session(code));

        Assert.notNull(sessionInfo,"code 无效");

        Assert.isTrue(0 == sessionInfo.getInteger("errcode"),sessionInfo.getString("errmsg"));

        // 获取用户唯一标识符 openid成功
        // 模拟从数据库获取用户信息
        User user = new User();
        user.setId(1L);
        Set authoritiesSet = new HashSet();
        // 模拟从数据库中获取用户权限
        authoritiesSet.add(new SimpleGrantedAuthority("test:add"));
        authoritiesSet.add(new SimpleGrantedAuthority("test:list"));
        authoritiesSet.add(new SimpleGrantedAuthority("ddd:list"));
        user.setAuthorities(authoritiesSet);
        HashMap<String,Object> hashMap = new HashMap<>();
        hashMap.put("id",user.getId().toString());
        hashMap.put("authorities",authoritiesSet);
        String token = JwtTokenUtil.generateToken(user);
        redisUtil.hset(token,hashMap);

        return GenericResponse.response(ServiceError.NORMAL,token);
    }

    /**
     * 登录凭证校验
     * @param code
     * @return
     * @throws Exception
     */
    private String jcode2Session(String code)throws Exception{
        String sessionInfo = Jcode2SessionUtil.jscode2session(appid,secret,code,"authorization_code");//登录grantType固定
        log.info(sessionInfo);
        return sessionInfo;
    }
}
```
### 控制层
```java
import com.lzw.security.common.GenericResponse;
import com.lzw.security.common.ServiceError;
import com.lzw.security.service.WeChatService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @Autowired
    private WeChatService weChatService;

    /**
     * code登录获取用户openid
     * @param code
     * @return
     * @throws Exception
     */
    @PostMapping("/login")
    public GenericResponse login(String code)throws Exception{
        return weChatService.wxLogin(code);
    }

    /**
     * 权限测试
     */

    @GetMapping("/test")
    public GenericResponse test(){
        return GenericResponse.response(ServiceError.NORMAL,"test");
    }

    @PostMapping("/test")
    public GenericResponse testPost(){
        return GenericResponse.response(ServiceError.NORMAL,"testPOST");
    }

    @GetMapping("/test/a")
    public GenericResponse testA(){
        return GenericResponse.response(ServiceError.NORMAL,"testManage");
    }

    @GetMapping("/hello")
    public GenericResponse hello(){
        return GenericResponse.response(ServiceError.NORMAL,"hello security");
    }

    @GetMapping("/ddd")
    @PreAuthorize("hasAuthority('ddd:list')")//基于表达式的权限验证，调用此方法需有 "ddd:list" 的权限
    public GenericResponse ddd(){
        return GenericResponse.response(ServiceError.NORMAL,"dddList");
    }

    @PostMapping("/ddd")
    @PreAuthorize("hasAuthority('ddd:add')")//基于表达式的权限验证，调用此方法需有 "ddd:list" 的权限
    public GenericResponse dddd(){
        return GenericResponse.response(ServiceError.NORMAL,"testPOST");
    }
}
```
## 工具类相关
### redis
```java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import java.util.HashMap;
import java.util.Set;
import java.util.concurrent.TimeUnit;
/**
 * redis工具类
 * @author: jamesluozhiwei
 */
@Component
public class RedisUtil {

    @Value("${token.expirationMilliSeconds}")
    private long expirationMilliSeconds;

    //@Autowired
    //private StringRedisTemplate redisTemplate;

    @Autowired
    private RedisTemplate redisTemplate;

    /**
     * 查询key,支持模糊查询
     * @param key
     * */
    public Set<String> keys(String key){
        return redisTemplate.keys(key);
    }

    /**
     * 字符串获取值
     * @param key
     * */
    public Object get(String key){
        return redisTemplate.opsForValue().get(key);
    }

    /**
     * 字符串存入值
     * 默认过期时间为2小时
     * @param key
     * */
    public void set(String key, String value){
        set(key,value,expirationMilliSeconds);
    }

    /**
     * 字符串存入值
     * @param expire 过期时间（毫秒计）
     * @param key
     * */
    public void set(String key, String value,long expire){
        redisTemplate.opsForValue().set(key,value, expire,TimeUnit.MILLISECONDS);
    }

    /**
     * 删出key
     * 这里跟下边deleteKey（）最底层实现都是一样的，应该可以通用
     * @param key
     * */
    public void delete(String key){
        redisTemplate.opsForValue().getOperations().delete(key);
    }

    /**
     * 添加单个
     * @param key    key
     * @param filed  filed
     * @param domain 对象
     */
    public void hset(String key,String filed,Object domain){
        hset(key,filed,domain,expirationMilliSeconds);
    }

    /**
     * 添加单个
     * @param key    key
     * @param filed  filed
     * @param domain 对象
     * @param expire 过期时间（毫秒计）
     */
    public void hset(String key,String filed,Object domain,long expire){
        redisTemplate.opsForHash().put(key, filed, domain);
        setKeyExpire(key,expirationMilliSeconds);
    }

    /**
     * 添加HashMap
     *
     * @param key    key
     * @param hm    要存入的hash表
     */
    public void hset(String key, HashMap<String,Object> hm){
        redisTemplate.opsForHash().putAll(key,hm);
        setKeyExpire(key,expirationMilliSeconds);
    }

    /**
     * 如果key存在就不覆盖
     * @param key
     * @param filed
     * @param domain
     */
    public void hsetAbsent(String key,String filed,Object domain){
        redisTemplate.opsForHash().putIfAbsent(key, filed, domain);
    }

    /**
     * 查询key和field所确定的值
     * @param key 查询的key
     * @param field 查询的field
     * @return HV
     */
    public Object hget(String key,String field) {
        return redisTemplate.opsForHash().get(key, field);
    }

    /**
     * 查询该key下所有值
     * @param key 查询的key
     * @return Map<HK, HV>
     */
    public Object hget(String key) {
        return redisTemplate.opsForHash().entries(key);
    }

    /**
     * 删除key下所有值
     *
     * @param key 查询的key
     */
    public void deleteKey(String key) {
        redisTemplate.opsForHash().getOperations().delete(key);
    }

    /**
     * 添加set集合
     * @param key
     * @param set
     * @param expire
     */
    public void sset(Object key,Set<?> set,long expire){
        redisTemplate.opsForSet().add(key,set);
        setKeyExpire(key,expire);
    }

    /**
     * 添加set集合
     * @param key
     * @param set
     */
    public void sset(Object key,Set<?> set){
        sset(key, set,expirationMilliSeconds);
    }

    /**
     * 判断key和field下是否有值
     * @param key 判断的key
     * @param field 判断的field
     */
    public Boolean hasKey(String key,String field) {
        return redisTemplate.opsForHash().hasKey(key,field);
    }

    /**
     * 判断key下是否有值
     * @param key 判断的key
     */
    public Boolean hasKey(String key) {
        return redisTemplate.opsForHash().getOperations().hasKey(key);
    }

    /**
     * 更新key的过期时间
     * @param key
     * @param expire
     */
    public void setKeyExpire(Object key,long expire){
        redisTemplate.expire(key,expire,TimeUnit.MILLISECONDS);
    }
}
```
### JWT生成解析工具
```java
import com.lzw.security.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.Date;
import java.util.Map;
/**
 * @author: jamesluozhiwei
 * @description: jwt生成token
 */
public class JwtTokenUtil {

    private static final String SALT = "123456";//加密解密盐值

    /**
     * 生成token(请根据自身业务扩展)
     * @param subject （主体信息）
     * @param expirationSeconds 过期时间（秒）
     * @param claims 自定义身份信息
     * @return
     */
    public static String generateToken(String subject, int expirationSeconds, Map<String,Object> claims) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)//主题
                //.setExpiration(new Date(System.currentTimeMillis() + expirationSeconds * 1000))
                .signWith(SignatureAlgorithm.HS512, SALT) // 不使用公钥私钥
                //.signWith(SignatureAlgorithm.RS256, privateKey)
                .compact();
    }

    /**
     * 生成token
     * @param user
     * @return
     */
    public static String generateToken(User user){
        return Jwts.builder()
                .setSubject(user.getId().toString())
                .setExpiration(new Date(System.currentTimeMillis()))
                .setIssuedAt(new Date())
                .setIssuer("JAMES")
                .signWith(SignatureAlgorithm.HS512, SALT)// 不使用公钥私钥
                .compact();
    }

    /**
     * 解析token,获得subject中的信息
     * @param token
     * @return
     */
    public static String parseToken(String token) {
        String subject = null;
        try {
            subject = getTokenBody(token).getSubject();
        } catch (Exception e) {
        }
        return subject;
    }

    /**
     * 获取token自定义属性
     * @param token
     * @return
     */
    public static Map<String,Object> getClaims(String token){
        Map<String,Object> claims = null;
        try {
            claims = getTokenBody(token);
        }catch (Exception e) {
        }

        return claims;
    }

    /**
     * 解析token
     * @param token
     * @return
     */
    private static Claims getTokenBody(String token){
        return Jwts.parser()
                //.setSigningKey(publicKey)
                .setSigningKey(SALT)
                .parseClaimsJws(token)
                .getBody();
    }
}
```
### 用户实体
注意用户实体需要实现 security 的 UserDetails
```java
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.util.Collection;
import java.util.Set;

public class User implements UserDetails, Serializable {

    private Long id;

    private String username;

    private String password;

    private Set<? extends GrantedAuthority> authorities;//权限列表

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public User setUsername(String username) {
        this.username = username;
        return this;
    }

    public User setPassword(String password) {
        this.password = password;
        return this;
    }

    public User setAuthorities(Set<? extends GrantedAuthority> authorities) {
        this.authorities = authorities;
        return this;
    }

    public Long getId() {
        return id;
    }

    public User setId(Long id) {
        this.id = id;
        return this;
    }
}
```
### 响应相关
```java
public class GenericResponse {

    private boolean success;
    private int statusCode;
    private Object content;
    private String msg;

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public Object getContent() {
        return content;
    }

    public void setContent(Object content) {
        this.content = content;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

    public GenericResponse(){}

    public GenericResponse(boolean success, int code, String msg, Object data) {

        this.success = success;
        this.statusCode = code;
        this.msg = msg;
        this.content = data;
    }

    public static GenericResponse response(ServiceError error) {

        return GenericResponse.response(error, null);
    }

    public static GenericResponse response(ServiceError error, Object data) {

        if (error == null) {
            error = ServiceError.UN_KNOW_ERROR;
        }
        if (error.equals(ServiceError.NORMAL)) {
            return GenericResponse.response(true, error.getCode(), error.getMsg(), data);
        }
        return GenericResponse.response(false, error.getCode(), error.getMsg(), data);
    }

    public static GenericResponse response(boolean success, int code, String msg, Object data) {

        return new GenericResponse(success, code, msg, data);
    }
}
```
```java
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
```
## springboot 启动类
jar启动请忽略，war启动请继承 SpringBootServletInitializer
```java
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

@SpringBootApplication
public class SecurityApplication extends SpringBootServletInitializer {

    public static void main(String[] args) {
        SpringApplication.run(SecurityApplication.class, args);
    }

    // war启动请实现该方法
    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder builder) {
        return builder.sources(SecurityApplication.class);
    }
}
```
# postman演示
未登录访问接口
![未登录访问接口](https://raw.githubusercontent.com/jamesluozhiwei/FigureBed/master/2019/springboot/security-not-login.png)

登录后携带token访问
![登录后携带token访问](https://raw.githubusercontent.com/jamesluozhiwei/FigureBed/master/2019/springboot/security-logined.png)
#项目地址
github地址：[https://github.com/jamesluozhiwei/security](https://github.com/jamesluozhiwei/security)

如果对您有帮助请高抬贵手点个star

---
个人博客：[https://www.cqwxhn.xin](https://www.cqwxhn.xin)    

关注公众号获取更多咨询

![Java开发小驿站](https://www.github.com/jamesluozhiwei/FigureBed/raw/master/2019/6/22/qrcode_for_gh_5926b81f45c6_258.jpg)
