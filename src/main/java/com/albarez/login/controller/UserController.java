package com.albarez.login.controller;

import com.albarez.login.request.LoginRequest;
import com.albarez.login.request.NewPasswordRequest;
import com.albarez.login.request.RegistrationRequest;
import com.albarez.login.service.UserDetailsServiceImpl;
import com.albarez.login.service.UserService;
import com.albarez.login.service.ResetPasswordService;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "api/v1/auth")
@AllArgsConstructor
public class UserController {

    private final UserService userService;
    private final UserDetailsServiceImpl userDetailsService;
    private final ResetPasswordService resetPasswordService;

    @PostMapping(path = "/signin")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        return userDetailsService.singin(request);
    }
    //http://localhost:8080/api/v1/signup
    @PostMapping(path = "/signup")
    public String register(@RequestBody RegistrationRequest request) {
        return userService.register(request);
    }

    //http://localhost:8080/api/v1/auth/signup/confirm?token=123456789
    @GetMapping(path = "/signup/confirm")
    public String confirm(@RequestParam("token") String token) {
        return userService.confirmToken(token);
    }

    //Recuperacion de contraseña ========================================================

    //http://localhost:8080/api/v1/auth/forgot-password?email=ejemplo@gmail.com
    @PostMapping(path = "/forgot-password")
    public String sendEmail(@RequestParam("email") String email) {
        return resetPasswordService.sendEmailForgotPassword(email);
    }

    //http://localhost:8080/api/v1/auth/forgot-password/reset?token=123456789
    @PostMapping(path = "forgot-password/reset")
    public String resetConfirm(@RequestBody NewPasswordRequest passwordRequest, @RequestParam("token") String token) {
        return resetPasswordService.confirmToken(passwordRequest, token);
    }

}
