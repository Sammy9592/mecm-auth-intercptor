package com.sl.mecm.auth.intercptor.token;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import com.sl.mecm.auth.intercptor.TestUtils;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;

@Slf4j
class RSASecurityTokenClientTest {

    private static final JSONObject TEST_PAYLOAD = JSONObject.of()
            .fluentPut("key1", "value1")
            .fluentPut("key2", 123);

    @Test
    void apply() {
        String jwtToken = new RSASecurityTokenClient.Builder()
                .defaultHeaders()
                .setCusPayload(TEST_PAYLOAD)
                .setRSAKey(TestUtils.getTestRSAClient().getPublicKey(), TestUtils.getTestRSAClient().getPrivateKey())
                .build()
                .apply();
        log.info("jwt token:" + jwtToken);
        Assertions.assertNotNull(jwtToken);
    }

    @Test
    void verify() {
        String jwtToken = new RSASecurityTokenClient.Builder()
                .defaultHeaders()
                .setCusPayload(TEST_PAYLOAD)
                .setRSAKey(TestUtils.getTestRSAClient().getPublicKey(), TestUtils.getTestRSAClient().getPrivateKey())
                .build()
                .apply();

        RSASecurityTokenClient client = new RSASecurityTokenClient.Loader()
                .of(jwtToken)
                .setRSAKey(TestUtils.getTestRSAClient().getPublicKey(), TestUtils.getTestRSAClient().getPrivateKey())
                .load();

        boolean result = client
                .verify();

        Assertions.assertTrue(result);
        JSONObject payload = JSON.parseObject(client.getPayload());
        Assertions.assertEquals(TEST_PAYLOAD.getString("key1"), payload.getString("key1"));
        Assertions.assertEquals(TEST_PAYLOAD.getInteger("key2"), payload.getInteger("key2"));
    }

    @Test
    void check_failed_for_require_attribute() {
        String jwtToken = new RSASecurityTokenClient.Builder()
                .defaultHeaders()
                .setCusPayload(TEST_PAYLOAD)
                .setRSAKey(TestUtils.getTestRSAClient().getPublicKey(), TestUtils.getTestRSAClient().getPrivateKey())
                .build()
                .apply();

        RSASecurityTokenClient client = new RSASecurityTokenClient.Loader()
                .of(jwtToken)
                .setRSAKey(TestUtils.getTestRSAClient().getPublicKey(), TestUtils.getTestRSAClient().getPrivateKey())
                .load();

        boolean result = client
                .check(JSONObject.of("requireKey", "value"));

        Assertions.assertFalse(result);
        JSONObject payload = JSON.parseObject(client.getPayload());
        Assertions.assertEquals(TEST_PAYLOAD.getString("key1"), payload.getString("key1"));
        Assertions.assertEquals(TEST_PAYLOAD.getInteger("key2"), payload.getInteger("key2"));
    }

    @Test
    void check_failed_for_expired() {
        String jwtToken = new RSASecurityTokenClient.Builder()
                .defaultHeaders()
                .setCusPayload(TEST_PAYLOAD)
                .setRSAKey(TestUtils.getTestRSAClient().getPublicKey(), TestUtils.getTestRSAClient().getPrivateKey())
                .setExpiredTimeSec(2)
                .build()
                .apply();

        RSASecurityTokenClient client = new RSASecurityTokenClient.Loader()
                .of(jwtToken)
                .setRSAKey(TestUtils.getTestRSAClient().getPublicKey(), TestUtils.getTestRSAClient().getPrivateKey())
                .load();

        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        boolean result = client
                .check(new JSONObject());

        Assertions.assertFalse(result);
        JSONObject payload = JSON.parseObject(client.getPayload());
        Assertions.assertEquals(TEST_PAYLOAD.getString("key1"), payload.getString("key1"));
        Assertions.assertEquals(TEST_PAYLOAD.getInteger("key2"), payload.getInteger("key2"));
    }
}