package com.sl.mecm.auth.intercptor.token;

import com.alibaba.fastjson2.JSONObject;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class RSASecurityTokenClient {

    private RSASecurityToken securityToken = new MECMAuthSecurityToken();

    private RSASecurityTokenClient(){}

    public String apply(){
        return securityToken.serialize();
    }

    public boolean verify(){
        return securityToken.verify();
    }

    public boolean check(JSONObject entitlement){
        return securityToken.check(entitlement);
    }

    public Map<String, Object> getHeaders() {
        return securityToken.getHeaders();
    }

    public String getPayload() {
        return securityToken.getPayload();
    }

    /**
     * create security client for new token
     */
    public static class Builder{

        private RSASecurityTokenClient theClient;

        public Builder(){
            theClient = new RSASecurityTokenClient();
        }

        public Builder setCusHeaders(Map<String, Object> cusHeaders){
            theClient.securityToken.setCusHeaders(cusHeaders);
            return this;
        }

        public Builder defaultHeaders(){
            theClient.securityToken.defaultHeaders();
            return this;
        }

        public Builder setCusPayload(Map<String, Object> cusPayload){
            theClient.securityToken.setCusPayload(cusPayload);
            return this;
        }

        public Builder setRSAKey(PublicKey publicKey, PrivateKey privateKey){
            theClient.securityToken.setRSAKey(publicKey, privateKey);
            return this;
        }

        public Builder setExpiredTimeSec(int seconds){
            theClient.securityToken.setExpiredTimeSec(seconds);
            return this;
        }

        public RSASecurityTokenClient build() {
            theClient.securityToken.create();
            return theClient;
        }
    }

    /**
     * create security client to load existing token
     */
    public static class Loader{

        private RSASecurityTokenClient theClient;

        public Loader(){
            theClient = new RSASecurityTokenClient();
        }

        public Loader of(String tokenStr){
            this.theClient.securityToken.of(tokenStr);
            return this;
        }

        public Loader setRSAKey(PublicKey publicKey, PrivateKey privateKey){
            theClient.securityToken.setRSAKey(publicKey, privateKey);
            return this;
        }

        public RSASecurityTokenClient load() {
            return theClient;
        }
    }
}
