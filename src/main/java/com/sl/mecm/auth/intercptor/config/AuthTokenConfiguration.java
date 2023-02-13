package com.sl.mecm.auth.intercptor.config;

import com.alibaba.fastjson2.JSONObject;
import com.sl.mecm.auth.intercptor.constant.AuthType;
import com.sl.mecm.core.commons.constants.CommonVariables;
import com.sl.mecm.core.commons.utils.JsonUtils;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.server.Session;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

import java.util.function.Consumer;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Configuration
@ConfigurationProperties(prefix = "mecm.auth.token")
@Slf4j
public class AuthTokenConfiguration implements InitializingBean {

    private Boolean enable;
    private String entitlement;

    public Boolean isEnable() {
        return enable;
    }

    public void setEnable(Boolean enable) {
        this.enable = enable;
    }

    public String getEntitlement() {
        return entitlement;
    }

    public JSONObject getEntitlementObject(){
        return JsonUtils.toJsonObject(entitlement);
    }

    public void setEntitlement(String entitlement) {
        this.entitlement = entitlement;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        if (enable == null) enable = true;
        if (!enable){
            return;
        }
        checkEmptyString(entitlement, "entitlement");
        Mono.just(entitlement)
                .map(theEntitlement -> {
                    if (!JsonUtils.isInvalid(theEntitlement)){
                        throwIllegalConfigException("entitlement", "entitlement is not valid json string");
                    }
                    return theEntitlement;
                })
                .map(JsonUtils::toJsonObject)
                .doOnNext(entitlementObject -> {
                    String type = entitlementObject.getString(CommonVariables.AUTH_TYPE);
                    if (AuthType.typeOf(type) == null){
                        throwIllegalConfigException("entitlement", "invalid auth type:" + type);
                    }
                })
                .doOnNext(entitlementObject -> {
                    String type = entitlementObject.getString(CommonVariables.AUTH_TYPE);
                    checkEmptyString(entitlementObject.getString(CommonVariables.SOURCE), "source");
                    switch (AuthType.typeOf(type)){
                       case SESSION_AUTH -> {
                           if (!entitlementObject.containsKey(CommonVariables.SESSION_TOKEN)){
                               throwIllegalConfigException(CommonVariables.SESSION_TOKEN, "you musts add [sessionToken] if auth type is [SEA]");
                           }
                       }
                       case CLIENT_AUTH -> {
                           checkEmptyString(entitlementObject.getString(CommonVariables.CLIENT_ID), "clientId");
                           checkEmptyString(entitlementObject.getString(CommonVariables.CLIENT_SECRET), "clientSecret");
                       }
                   }
                })
                .block();
    }

    private void checkEmptyString(String text, String keyName){
        if (!StringUtils.hasText(text)){
            throwIllegalConfigException(keyName, keyName + " must be not empty");
        }
    }

    private void throwIllegalConfigException(String name, String msg){
        String errorMsg = "invalid auth token config with name:" + name + ", by:" + msg;
        log.error(errorMsg);
        throw new IllegalArgumentException(errorMsg);
    }
}
