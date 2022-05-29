package com.albarez.login.payload.request;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import javax.validation.constraints.NotBlank;
import java.io.Serial;
import java.io.Serializable;

@Getter
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class LoginRequest implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;
    @NotBlank
    private String email;
    @NotBlank
    private String password;
}
