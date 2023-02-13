package com.sl.mecm.auth.intercptor.constant;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static com.sl.mecm.auth.intercptor.constant.AuthType.SESSION_AUTH;
import static com.sl.mecm.auth.intercptor.constant.AuthType.UNKNOWN_TYPE;
import static org.junit.jupiter.api.Assertions.*;

class AuthTypeTest {

    @Test
    void typeOf() {
        AuthType authType = AuthType.typeOf("SEA");
        Assertions.assertEquals(SESSION_AUTH, authType);
    }

    @Test
    void typeOf_unknown() {
        AuthType authType = AuthType.typeOf("unknown_123");
        Assertions.assertEquals(UNKNOWN_TYPE, authType);
    }
}