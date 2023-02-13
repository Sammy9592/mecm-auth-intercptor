package com.sl.mecm.auth.intercptor.config;

import com.nimbusds.jose.jwk.RSAKey;
import com.sl.mecm.core.commons.security.RSAClient;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Configuration
public class SecurityKeyConfig {

    @Bean("tokenRSAClient")
    public RSAClient getTokenRSAClient(){
        return new RSAClient.Builder()
                .setFilePath("tokenkey.p12")
                .setStorePwd("mecmkeystore120966815#")
                .setAlias("tokenPrivateKey")
                .setPrivateKeyPwd("mecmkeystore120966815#")
                .build();
    }

    @Bean("tokenRSAKey")
    public RSAKey getTokenRSAKey(RSAClient tokenRSAClient){
        return new RSAKey.Builder((RSAPublicKey) tokenRSAClient.getPublicKey())
                .privateKey(tokenRSAClient.getPrivateKey())
                .build();
    }

    @Bean("tokenPublicKey")
    public PublicKey getTokenPublicKey(RSAClient tokenRSAClient){
        return tokenRSAClient.getPublicKey();
    }

    @Bean("tokenPrivateKey")
    public PrivateKey getTokenPrivateKey(RSAClient tokenRSAClient){
        return tokenRSAClient.getPrivateKey();
    }
}
