package com.lzw.security.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * redis工具类
 * @author jamesluozhiwei
 */
@Component
public class RedisUtil {

    @Value("${token.expirationMilliSeconds}")
    private long expirationMilliSeconds;

    @Autowired
    private RedisTemplate<Object, Object> redisTemplate;

    /**
     * 查询key,支持模糊查询
     * @param key 键
     * @return set集合
     */
    public Set<Object> keys(String key){
        return redisTemplate.keys(key);
    }

    /**
     * 字符串获取值
     * @param key 键
     *
     */
    public Object get(String key){
        return redisTemplate.opsForValue().get(key);
    }

    /**
     * 字符串存入值
     * 默认过期时间为2小时
     * @param key 键
     */
    public void set(String key, String value){
        set(key,value,expirationMilliSeconds);
    }

    /**
     * 字符串存入值
     * @param expire 过期时间（毫秒计）
     * @param key 键
     */
    public void set(String key, String value,long expire){
        redisTemplate.opsForValue().set(key,value, expire,TimeUnit.MILLISECONDS);
    }

    /**
     * 删出key
     * 这里跟下边deleteKey（）最底层实现都是一样的，应该可以通用
     * @param key 键
     */
    public void delete(String key){
        redisTemplate.opsForValue().getOperations().delete(key);
    }

    /**
     * 添加单个
     * @param key    key
     * @param filed  filed
     * @param domain 对象
     */
    public void hashSet(String key,String filed,Object domain){
        hashSet(key,filed,domain,expirationMilliSeconds);
    }

    /**
     * 添加单个
     * @param key    key
     * @param filed  filed
     * @param domain 对象
     * @param expire 过期时间（毫秒计）
     */
    public void hashSet(String key, String filed, Object domain, long expire){
        redisTemplate.opsForHash().put(key, filed, domain);
        setKeyExpire(key,expirationMilliSeconds);
    }

    /**
     * 添加HashMap
     * @param key    key
     * @param hm    要存入的hash表
     */
    public void hashSet(String key, HashMap<String,Object> hm){
        redisTemplate.opsForHash().putAll(key,hm);
        setKeyExpire(key,expirationMilliSeconds);
    }

    /**
     * 如果key存在就不覆盖
     * @param key 键
     * @param filed 字段
     * @param domain 值
     */
    public void hashSetAbsent(String key,String filed,Object domain){
        redisTemplate.opsForHash().putIfAbsent(key, filed, domain);
    }

    /**
     * 查询key和field所确定的值
     * @param key 查询的key
     * @param field 查询的field
     * @return HV
     */
    public Object hashGet(String key,String field) {
        return redisTemplate.opsForHash().get(key, field);
    }

    /**
     * 查询该key下所有值
     * @param key 查询的key
     * @return Map<HK, HV>
     */
    public Object hashGet(String key) {
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
     * @param key 键
     * @param set   集合
     * @param expire    过期时间
     */
    public void setSet(Object key, Set<?> set, long expire){
        redisTemplate.opsForSet().add(key,set);
        setKeyExpire(key,expire);
    }

    /**
     * 添加set集合
     * @param key 键
     * @param set 集合
     */
    public void setSet(Object key, Set<?> set){
        setSet(key, set,expirationMilliSeconds);
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
     * @param key 键
     * @param expire 过期时间
     */
    public void setKeyExpire(Object key,long expire){
        redisTemplate.expire(key,expire,TimeUnit.MILLISECONDS);
    }

}
