package com.albarez.login.payload.request;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;

@Getter
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class LoginRequest implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;
    private final String email;
    private final String password;
}
