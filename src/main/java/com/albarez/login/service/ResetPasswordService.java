package com.albarez.login.service;

import com.albarez.login.email.EmailSender;
import com.albarez.login.model.*;
import com.albarez.login.model.repository.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.time.LocalDateTime;

@Service
@AllArgsConstructor
public class ResetPasswordService {

    private final static String USER_NOT_FOUND_MSG = "Usuario con email %s no encontrado";
    private final UserService userService;
    private final UserRepository userRepository;
    private final ConfirmationTokenService confirmationTokenService;
    private final EmailSender emailSender;

    public String sendEmailForgotPassword(String email) {
        User user = userRepository.findByEmail(email).orElseThrow(() -> new IllegalStateException(String.format(USER_NOT_FOUND_MSG, email)));
        String token = userService.resetPasswordToken(email, user);
        String link = "http://localhost:8080/api/v1/registration/reset-password/confirm?token=" + token;
        emailSender.send(email, buildEmail(user.getFirstName(), link));

        return token;
    }

    @Transactional
    public String confirmToken(NewPasswordRequest request, String token) {

        ConfirmationToken confirmationToken = confirmationTokenService.getToken(token).orElseThrow(
                () -> new IllegalStateException("Token no encontrado"));
        if (!request.getPassword().equals(request.getPasswordConfirmation())) {
            throw new IllegalStateException("Las contraseñas no coinciden");
        }
        if (confirmationToken.getConfirmedAt() != null) {
            throw new IllegalStateException("Token ya confirmado");
        }

        LocalDateTime expiredAt = confirmationToken.getExpiresAt();

        if (expiredAt.isBefore(LocalDateTime.now())) {
            throw new IllegalStateException("Token expirado");
        }

        confirmationTokenService.setConfirmedAt(token);
        userService.updatePassword(request.getPassword(), confirmationToken.getUser().getEmail());
        userService.enableUser(confirmationToken.getUser().getEmail());

        return "Password reset successfully";
    }

    private String buildEmail(String firstName, String link) {
        return "<h1>Hola " + firstName + "</h1>" +
                "<p>Hemos recibido una petición para restablecer la contraseña de tu cuenta.</p>" +
                "<p>Si hiciste esta petición, haz clic en el siguiente enlace, si no hiciste esta petición puedes ignorar este correo.</p>" +
                "<p> <a href=\"" + link + "\">Restablecer contraseña</a> </p>" +
                "<p>Saludos,</p>" +
                "<p>Equipo de Login</p>";
    }
}

// End of file






