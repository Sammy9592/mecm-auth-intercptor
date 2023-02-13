package com.sl.mecm.auth.intercptor.exception;

import com.sl.mecm.core.commons.entity.AppResponse;

public class MECMAuthTokenException extends RuntimeException{

    private final String code;
    private final AppResponse responseBody;

    public MECMAuthTokenException(String code, String message, AppResponse responseBody) {
        super(message);
        this.code = code;
        this.responseBody = responseBody;
    }

    public MECMAuthTokenException(String code, String message, AppResponse responseBody, Throwable cause) {
        super(message, cause);
        this.code = code;
        this.responseBody = responseBody;
    }

    public String getCode() {
        return code;
    }

    public AppResponse getResponseBody() {
        return responseBody;
    }
}
