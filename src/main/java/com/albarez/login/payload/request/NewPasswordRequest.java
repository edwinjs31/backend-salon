package com.albarez.login.payload.request;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

@Getter
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class NewPasswordRequest {
    private final String password;
    private final String passwordConfirmation;
}
