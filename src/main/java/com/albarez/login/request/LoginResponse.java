package com.albarez.login.request;

import java.io.Serial;
import java.io.Serializable;

public class LoginResponse implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;
    private final String jwt;

    public LoginResponse(String jwt) {
        this.jwt = jwt;
    }

    public String getJwt() {
        return jwt;
    }
}
