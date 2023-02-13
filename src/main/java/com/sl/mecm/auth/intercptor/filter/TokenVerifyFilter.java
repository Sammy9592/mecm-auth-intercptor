package com.sl.mecm.auth.intercptor.filter;

import com.alibaba.fastjson2.JSONObject;
import com.sl.mecm.auth.intercptor.config.AuthTokenConfiguration;
import com.sl.mecm.auth.intercptor.exception.MECMAuthTokenException;
import com.sl.mecm.auth.intercptor.service.TokenVerifyService;
import com.sl.mecm.core.commons.constants.CommonVariables;
import com.sl.mecm.core.commons.entity.AppResponse;
import com.sl.mecm.core.commons.exception.ErrorCode;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import java.nio.charset.StandardCharsets;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class TokenVerifyFilter implements WebFilter {

    @Autowired
    private TokenVerifyService tokenVerifyService;

    @Autowired
    private AuthTokenConfiguration authTokenConfiguration;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        if (!authTokenConfiguration.isEnable()){
            log.warn("your API is not security");
            return chain.filter(exchange);
        }
        return Mono.just(exchange)
                .doOnNext(theExchange -> {
                    String tokenStr = theExchange.getRequest().getHeaders().getFirst(CommonVariables.MECM_TRUST_TOKEN);
                    if (!StringUtils.hasText(tokenStr)) {
                        log.warn("Auth token not found!");
                        throw new MECMAuthTokenException(ErrorCode.NO_AUTH.getCode(), "No auth attributes be found!",
                                new AppResponse(ErrorCode.NO_AUTH.getCode(), "Invalid Token!", null));
                    }
                })
                .flatMap(theExchange -> {
                    String tokenStr = theExchange.getRequest().getHeaders().getFirst(CommonVariables.MECM_TRUST_TOKEN);
                    tokenVerifyService.verify(tokenStr, theExchange.getRequest());
                    return chain.filter(theExchange);
                })
                .onErrorResume(MECMAuthTokenException.class, e ->
                        errorResponse(exchange, e.getResponseBody().toJSONObject(), e));
    }

    private Mono<Void> errorResponse(ServerWebExchange exchange, JSONObject responseBody, Throwable throwable){
        log.warn("error on verify token:" + throwable.getLocalizedMessage(), throwable);
        return Mono.defer(() -> Mono.just(exchange.getResponse()))
                .flatMap(response -> {
                    byte[] body = responseBody.toString().getBytes(StandardCharsets.UTF_8);
                    response.setStatusCode(HttpStatus.UNAUTHORIZED);
                    response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
                    DataBuffer buffer = response.bufferFactory().wrap(body);
                    return response.writeWith(Mono.just(buffer).doOnError(e -> {
                        log.warn("error to write response body:" + e.getLocalizedMessage());
                        DataBufferUtils.release(buffer);
                    }));
                });
    }
}
