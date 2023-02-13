package com.sl.mecm.auth.intercptor.token;

import com.alibaba.fastjson2.JSONObject;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

public interface RSASecurityToken {

    void create();

    void of(String tokenStr);

    String serialize();

    boolean check(JSONObject entitlement);

    boolean verify();

    void setCusHeaders(Map<String, Object> cusHeaders);

    void defaultHeaders();

    void setCusPayload(Map<String, Object> payload);

    void setRSAKey(PublicKey publicKey, PrivateKey privateKey);

    void setExpiredTimeSec(int seconds);

    Map<String, Object> getHeaders();

    String getPayload();
}
