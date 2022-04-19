package com.albarez.login.controller;

import com.albarez.login.request.LoginRequest;
import com.albarez.login.request.NewPasswordRequest;
import com.albarez.login.request.RegistrationRequest;
import com.albarez.login.service.UserService;
import com.albarez.login.service.ResetPasswordService;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping(path = "api/v1/auth")
@AllArgsConstructor
public class AuthController {

    @Autowired
    private final UserService userService;
    @Autowired
    private final ResetPasswordService resetPasswordService;

    //http://localhost:8080/api/v1/signin
    @PostMapping(path = "/signin")
    public ResponseEntity<?> login(@Validated @RequestBody LoginRequest request) {
        return userService.authenticateUser(request.getEmail(), request.getPassword());
    }

    //http://localhost:8080/api/v1/signup
    @PostMapping(path = "/signup")
    public ResponseEntity<?> register(@Validated @RequestBody RegistrationRequest request) {
        return userService.register(request);
    }

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
    public String sendEmail(@RequestParam("email") String email) {
        return resetPasswordService.sendEmailForgotPassword(email);
    }

    //http://localhost:8080/api/v1/auth/forgot-password/reset?token=123456789
    @PostMapping(path = "forgot-password/reset")
    public String resetConfirm(@RequestBody NewPasswordRequest passwordRequest, @RequestParam("token") String token) {
        return resetPasswordService.confirmToken(passwordRequest, token);
    }

}
