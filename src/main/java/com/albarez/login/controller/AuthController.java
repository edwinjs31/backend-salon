package com.albarez.login.controller;


import com.albarez.login.payload.request.LoginRequest;
import com.albarez.login.payload.request.NewPasswordRequest;
import com.albarez.login.payload.request.RegistrationRequest;
import com.albarez.login.service.UserService;
import com.albarez.login.service.ResetPasswordService;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping(path = "api/v1/auth")
@AllArgsConstructor
public class AuthController {

    @Autowired
    UserService userService;
    @Autowired
    ResetPasswordService resetPasswordService;

    //http://localhost:8080/api/v1/auth/signin
    @PostMapping(path = "/signin")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {
        return userService.authenticateUser(loginRequest.getEmail(), loginRequest.getPassword());
    }

    //http://localhost:8080/api/v1/auth/signup
    @PostMapping(path = "/signup")
    public ResponseEntity<?> register(@Valid @RequestBody RegistrationRequest registrationRequest) {
        return userService.register(registrationRequest);
    }

    //http://localhost:8080/api/v1/auth/signout
    @PostMapping("/signout")
    public ResponseEntity<?> logoutUser() {
        return userService.logoutUser();
    }

    //http://localhost:8080/api/v1/auth/signup/confirm?token=123456789
    @GetMapping(path = "/signup/confirm")
    public String confirm(@RequestParam("token") String token) {
        return userService.confirmToken(token);
    }

    //Recuperacion de contraseña ========================================================

    //http://localhost:8080/api/v1/auth/forgot-password?email=ejemplo@gmail.com
    @PostMapping(path = "/forgot-password")
    public ResponseEntity<?> sendEmail(@RequestParam("email") String email) {
        return resetPasswordService.sendEmailForgotPassword(email);
    }

    //http://localhost:8080/api/v1/auth/forgot-password/reset?token=123456789
    @PostMapping(path = "forgot-password/reset")
    public ResponseEntity<?> resetConfirm(@RequestBody NewPasswordRequest passwordRequest, @RequestParam("token") String token) {
        return resetPasswordService.confirmToken(passwordRequest, token);
    }

}
