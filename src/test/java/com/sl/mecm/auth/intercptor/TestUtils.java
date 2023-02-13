package com.sl.mecm.auth.intercptor;

import com.nimbusds.jose.jwk.RSAKey;
import com.sl.mecm.core.commons.security.RSAClient;

import java.security.interfaces.RSAPublicKey;

public class TestUtils {

    private static final RSAClient testRSAClient = new RSAClient.Builder()
            .setFilePath("tokenkey.p12")
            .setStorePwd("mecmkeystore120966815#")
            .setAlias("tokenPrivateKey")
            .setPrivateKeyPwd("mecmkeystore120966815#")
            .build();

    private static final RSAKey testRSAKey = new RSAKey.Builder((RSAPublicKey) testRSAClient.getPublicKey())
            .privateKey(testRSAClient.getPrivateKey())
            .build();

    public static RSAClient getTestRSAClient(){
        return testRSAClient;
    }

    public static RSAKey getTestRSAKey(){
        return testRSAKey;
    }
}
