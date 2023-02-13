package com.sl.mecm.auth.intercptor.token;

import com.alibaba.fastjson2.JSONObject;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.sl.mecm.auth.intercptor.exception.MECMAuthTokenException;
import com.sl.mecm.core.commons.exception.ErrorCode;
import com.sl.mecm.core.commons.utils.DateUtils;
import com.sl.mecm.core.commons.utils.UUIDTool;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class MECMAuthSecurityToken implements RSASecurityToken{

    private static final int DEFAULT_EXPIRED_SECONDS = 30;
    private static final String DEFAULT_ISSUER = "mecm_auth_service";
    private static final String DEFAULT_SUBJECT = "auth_jwt";
    private static final String DEFAULT_AUDIENCE = "mecm_app";

    private RSAKey rsaKey;
    private SignedJWT signedJWT;
    private JWSHeader jwsHeader;
    private JWTClaimsSet claimsSet;
    private Map<String, Object> cusPayload;
    private int expiredTimeSec = DEFAULT_EXPIRED_SECONDS;

    @Override
    public void create() {
        claimsSet = buildClaims(cusPayload);
        signedJWT = new SignedJWT(jwsHeader, claimsSet);
        try {
            signedJWT.sign(new RSASSASigner(this.rsaKey));
        } catch (Exception e) {
            throw new MECMAuthTokenException(ErrorCode.ERROR.getCode(), e.getMessage(), null, e);
        }
    }

    @Override
    public void of(String tokenStr) {
        try {
            signedJWT = SignedJWT.parse(tokenStr);
            claimsSet = signedJWT.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new MECMAuthTokenException(ErrorCode.ERROR.getCode(), e.getMessage(), null, e);
        }
        jwsHeader = signedJWT.getHeader();
    }

    @Override
    public String serialize() {
        return signedJWT.serialize();
    }

    @Override
    public boolean verify() {
        try {
            return signedJWT.verify(new RSASSAVerifier(rsaKey.toPublicJWK()));
        } catch (JOSEException e) {
            log.warn("token signature verify failed by:" + e.getMessage(), e);
            return false;
        }
    }

    @Override
    public boolean check(JSONObject entitlement) {
        JWTClaimsSet.Builder verifyBuilder = new JWTClaimsSet.Builder()
                .issuer(DEFAULT_ISSUER)
                .audience(DEFAULT_AUDIENCE)
                .subject(DEFAULT_SUBJECT);
        entitlement.forEach(verifyBuilder::claim);
        DefaultJWTClaimsVerifier<?> claimsVerifier = new DefaultJWTClaimsVerifier<>(
                verifyBuilder.build(),
                new HashSet<>(Arrays.asList("exp", "nbf", "jti")));
        claimsVerifier.setMaxClockSkew(0);
        try {
            claimsVerifier.verify(claimsSet, null);
            return true;
        } catch (BadJWTException e) {
            log.warn("token claim verify failed by:" + e.getMessage(), e);
            return false;
        }
    }

    @Override
    public void setCusHeaders(Map<String, Object> cusHeaders) {
        jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JWT)
                .customParams(cusHeaders)
                .build();
    }

    @Override
    public void defaultHeaders() {
        jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JWT)
                .build();
    }

    @Override
    public void setCusPayload(Map<String, Object> payload) {
        this.cusPayload = payload;
    }

    @Override
    public void setRSAKey(PublicKey publicKey, PrivateKey privateKey) {
        this.rsaKey = new RSAKey.Builder((RSAPublicKey) publicKey).privateKey(privateKey).build();
    }

    @Override
    public void setExpiredTimeSec(int seconds) {
        this.expiredTimeSec = seconds;
    }

    @Override
    public Map<String, Object> getHeaders() {
        return jwsHeader.toJSONObject();
    }

    @Override
    public String getPayload() {
        return claimsSet.toString();
    }

    private JWTClaimsSet buildClaims(Map<String, Object> cusPayload){
        Date nowDate = DateUtils.getNow();
        Date expiredDate = DateUtils.getDateAfterSeconds(expiredTimeSec);
        String jwtId = UUIDTool.applyUUID36();
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(DEFAULT_ISSUER)
                .audience(DEFAULT_AUDIENCE)
                .subject(DEFAULT_SUBJECT)
                .expirationTime(expiredDate)
                .notBeforeTime(nowDate)
                .issueTime(nowDate)
                .jwtID(jwtId);
        cusPayload.forEach(builder::claim);
        return builder.build();
    }
}
