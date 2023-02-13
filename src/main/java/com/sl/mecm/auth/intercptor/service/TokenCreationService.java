package com.sl.mecm.auth.intercptor.service;

import com.alibaba.fastjson2.JSONObject;
import com.sl.mecm.auth.intercptor.constant.AuthType;
import com.sl.mecm.auth.intercptor.token.RSASecurityTokenClient;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
import java.security.PublicKey;

@Service
public class TokenCreationService {

    @Autowired
    private PublicKey tokenPublicKey;

    @Autowired
    private PrivateKey tokenPrivateKey;

    public String generateToken(JSONObject authCerts, AuthType authType){
        return new RSASecurityTokenClient.Builder()
                .defaultHeaders()
                .setCusPayload(authCerts)
                .setRSAKey(tokenPublicKey, tokenPrivateKey)
                .setExpiredTimeSec(authType.getTokenTimeoutSec())
                .build()
                .apply();
    }
}
