package com.albarez.login.service;

import com.albarez.login.model.User;
import com.albarez.login.model.UserRole;
import com.albarez.login.request.RegistrationRequest;
import com.albarez.login.email.EmailSender;
import com.albarez.login.security.token.ConfirmationToken;
import com.albarez.login.security.token.ConfirmationTokenService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.time.LocalDateTime;

@Service
@AllArgsConstructor
public class UserService {

    private final UserDetailsServiceImpl userDetailsService;
    private final EmailValidator emailValidator;
    private final ConfirmationTokenService confirmationTokenService;
    private final EmailSender emailSender;


    public String register(RegistrationRequest request) {

        boolean isValidEmail = emailValidator.test(request.getEmail());
        if (!isValidEmail) {
            throw new IllegalArgumentException("Email inválido");
        }

        String token = userDetailsService.singUpUser(new User(
                request.getFirstName(),
                request.getLastName(),
                request.getEmail(),
                request.getPassword(),
                UserRole.USER)
        );

        String link = "http://localhost:8080/api/v1/auth/signup/confirm?token=" + token;
        emailSender.send(request.getEmail(), buildEmail(request.getFirstName(), link));

        return token;
    }

    @Transactional
    public String confirmToken(String token) {

        ConfirmationToken confirmationToken = confirmationTokenService.getToken(token).orElseThrow(
                () -> new IllegalStateException("Token no encontrado"));

        if (confirmationToken.getConfirmedAt() != null) {
            throw new IllegalStateException("Email ya está confirmado");
        }

        LocalDateTime expiredAt = confirmationToken.getExpiresAt();

        if (expiredAt.isBefore(LocalDateTime.now())) {
            throw new IllegalStateException("Token expirado");
        }

        confirmationTokenService.setConfirmedAt(token);
        userDetailsService.enableUser(confirmationToken.getUser().getEmail());

        return "Email confirmado";
    }


    private String buildEmail(String name, String link) {
        return "<h3>Hola " + name + "</h3>" +
                "<p>Te has registrado en AppSalon:</p>" +
                "<p>Para confirmar tu email haz click en el siguiente enlace:</p>" +
                "<a href=\"" + link + "\">Confirmar email</a>" +
                "<p>Saludos,</p>" +
                "<p>Equipo de AppSalon</p>";
    }
}
