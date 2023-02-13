package com.sl.mecm.auth.intercptor.constant;

import java.util.EnumSet;

public enum AuthType {

    SESSION_AUTH("SEA", 10), CLIENT_AUTH("CLA", 10), UNKNOWN_TYPE("N/A", 0);

    private final String type;
    private final int tokenTimeoutSec;

    AuthType(String type, int tokenTimeoutSec){
        this.type = type;
        this.tokenTimeoutSec = tokenTimeoutSec;
    }

    public String getType() {
        return type;
    }

    public int getTokenTimeoutSec() {
        return tokenTimeoutSec;
    }

    public static AuthType typeOf(String type){
        return EnumSet.allOf(AuthType.class)
                .stream()
                .filter(authType -> authType.type.equals(type))
                .findFirst()
                .orElseGet(() -> UNKNOWN_TYPE);
    }
}
