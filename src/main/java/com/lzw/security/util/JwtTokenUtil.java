package com.lzw.security.util;


import com.lzw.security.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;

import java.util.Date;
import java.util.Map;

/**
 * jwt生成token
 * @author jamesluozhiwei
 */
@Slf4j
public class JwtTokenUtil {

    /**
     * 加密解密盐值
     */
    private static final String SALT = "123456";

    /**
     * 生成token(请根据自身业务扩展)
     * @param subject （主体信息）
     * @param expirationSeconds 过期时间（秒）
     * @param claims 自定义身份信息
     * @return token
     */
    public static String generateToken(String subject, int expirationSeconds, Map<String,Object> claims) {
        return Jwts.builder()
                .setClaims(claims)
                //主题
                .setSubject(subject)
                //.setExpiration(new Date(System.currentTimeMillis() + expirationSeconds * 1000))
                //签名
                .signWith(SignatureAlgorithm.HS512, SALT)
                .compact();
    }

    /**
     * 生成token
     * @param user 用户信息
     * @return token
     */
    public static String generateToken(User user){
        return Jwts.builder()
                .setSubject(user.getId().toString())
                .setExpiration(new Date(System.currentTimeMillis()))
                .setIssuedAt(new Date())
                .setIssuer("JAMES")
                .signWith(SignatureAlgorithm.HS512, SALT)
                .compact();
    }

    /**
     * 解析token,获得subject中的信息
     * @param token 需解析的token
     * @return subject
     */
    public static String parseToken(String token) {
        String subject = null;
        try {
            subject = getTokenBody(token).getSubject();
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return subject;
    }

    /**
     * 获取token自定义属性
     * @param token token
     * @return  自定义属性集合
     */
    public static Map<String,Object> getClaims(String token){
        Map<String,Object> claims = null;
        try {
            claims = getTokenBody(token);
        }catch (Exception e) {
            log.error(e.getMessage());
        }
        return claims;
    }


    /**
     * 解析token
     * @param token 需解析的token
     * @return Claims
     */
    private static Claims getTokenBody(String token){
        return Jwts.parser()
                .setSigningKey(SALT)
                .parseClaimsJws(token)
                .getBody();
    }
}