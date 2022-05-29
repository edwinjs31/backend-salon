package com.albarez.login.payload.request;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

@Getter
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class NewPasswordRequest {
    @NotBlank
    @Size(min = 6, max = 40)
    private  String password;
    @NotBlank
    @Size(min = 6, max = 40)
    private  String passwordConfirmation;
}
