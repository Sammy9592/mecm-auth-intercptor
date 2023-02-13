package com.sl.mecm.auth.intercptor.service;

import com.alibaba.fastjson2.JSONObject;
import com.sl.mecm.auth.intercptor.config.AuthTokenConfiguration;
import com.sl.mecm.auth.intercptor.constant.AuthType;
import com.sl.mecm.auth.intercptor.exception.MECMAuthTokenException;
import com.sl.mecm.auth.intercptor.token.RSASecurityTokenClient;
import com.sl.mecm.core.commons.constants.CommonVariables;
import com.sl.mecm.core.commons.entity.AppResponse;
import com.sl.mecm.core.commons.exception.ErrorCode;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.security.PrivateKey;
import java.security.PublicKey;

@Service
public class TokenVerifyService {

    @Autowired
    private PublicKey tokenPublicKey;

    @Autowired
    private PrivateKey tokenPrivateKey;

    @Autowired
    private AuthTokenConfiguration authTokenConfiguration;

    public void verify(String tokenStr, ServerHttpRequest request){
        Assert.hasText(tokenStr, "token must be not empty");
        RSASecurityTokenClient client = new RSASecurityTokenClient.Loader()
                .of(tokenStr)
                .setRSAKey(tokenPublicKey, tokenPrivateKey)
                .load();
        JSONObject entitlement = retrieveEntitlement(request);
        this.verifyTokenSign(client).checkContent(client, entitlement);
    }

    private JSONObject retrieveEntitlement(ServerHttpRequest request){
        JSONObject entitlementObject = authTokenConfiguration.getEntitlementObject();
        String typeStr = entitlementObject.getString(CommonVariables.AUTH_TYPE);
        AuthType authType = AuthType.typeOf(typeStr);
        switch (authType){
            case SESSION_AUTH -> {
                String sessionToken = request.getHeaders().getFirst(CommonVariables.SESSION_TOKEN);
                if (!StringUtils.hasText(sessionToken)){
                    throw new MECMAuthTokenException(ErrorCode.NO_AUTH.getCode(), "lack of session token!",
                            new AppResponse(ErrorCode.NO_AUTH.getCode(), "Missing Auth Credential!", null));
                }
                entitlementObject.put(CommonVariables.SESSION_TOKEN, sessionToken);
                return entitlementObject;
            }

            case CLIENT_AUTH -> {
                return entitlementObject;
            }

            default -> throw new MECMAuthTokenException(ErrorCode.NO_AUTH.getCode(), "invalid auth type:" + authType,
                    new AppResponse(ErrorCode.NO_AUTH.getCode(), "Invalid Auth Credential!", null));
        }
    }

    private TokenVerifyService verifyTokenSign(RSASecurityTokenClient client){
        if (!client.verify()){
            AppResponse response = new AppResponse(ErrorCode.NO_AUTH.getCode(), "Invalid Auth Token!", null);
            throw new MECMAuthTokenException(ErrorCode.NO_AUTH.getCode(), "Invalid Auth Token!", response);
        }
        return this;
    }

    private void checkContent(RSASecurityTokenClient client, JSONObject entitlement){
        if (!client.check(entitlement)){
            AppResponse response = new AppResponse(ErrorCode.NO_AUTH.getCode(), "Token expired or invalid content!", null);
            throw new MECMAuthTokenException(ErrorCode.NO_AUTH.getCode(), "Token expired or invalid content!", response);
        }
    }
}
