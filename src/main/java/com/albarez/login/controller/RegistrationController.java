package com.albarez.login.controller;

import com.albarez.login.model.NewPasswordRequest;
import com.albarez.login.model.RegistrationRequest;
import com.albarez.login.service.RegistrationService;
import com.albarez.login.service.ResetPasswordService;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "api/v1/registration")
@AllArgsConstructor
public class RegistrationController {

    private final RegistrationService registrationService;
    private final ResetPasswordService resetPasswordService;

    //http://localhost:8080/api/v1/registration
    @PostMapping
    public String register(@RequestBody RegistrationRequest request) {
        return registrationService.register(request);
    }

    //http://localhost:8080/api/v1/registration/confirm?token=123456789
    @GetMapping(path = "confirm")
    public String confirm(@RequestParam("token") String token) {
        return registrationService.confirmToken(token);
    }

    //Recuperacion de contraseña ========================================================

    //http://localhost:8080/api/v1/registration/forgot-password
    @PostMapping(path = "/forgot-password")
    public String sendEmail(@RequestParam("email") String email) {
        return resetPasswordService.sendEmailForgotPassword(email);
    }

    //http://localhost:8080/api/v1/registration/reset-password/confirm?token=123456789
    @PostMapping(path = "reset-password/confirm")
    public String resetConfirm(@RequestBody NewPasswordRequest passwordRequest, @RequestParam("token") String token) {
        return resetPasswordService.confirmToken(passwordRequest, token);
    }

}
