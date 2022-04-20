package com.albarez.login.service;

import com.albarez.login.model.User;
import com.albarez.login.model.UserRole;
import com.albarez.login.repository.UserRepository;
import com.albarez.login.payload.request.RegistrationRequest;
import com.albarez.login.email.EmailSender;
import com.albarez.login.payload.response.MessageResponse;
import com.albarez.login.security.jwt.JwtUtil;
import com.albarez.login.security.token.ConfirmationToken;
import com.albarez.login.security.token.ConfirmationTokenService;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.time.LocalDateTime;
import java.util.UUID;

@Service
@AllArgsConstructor
public class UserService {

    @Autowired
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    @Autowired
    private final UserRepository userRepository;
    @Autowired
    private final EmailValidator emailValidator;
    @Autowired
    private final ConfirmationTokenService confirmationTokenService;
    @Autowired
    private final EmailSender emailSender;
    @Autowired
    private final AuthenticationManager authenticationManager;
    @Autowired
    private final JwtUtil jwtUtil;


    public ResponseEntity<?> authenticateUser(String email, String password) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
        if (!authentication.isAuthenticated()) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Usuario o contraseña incorrectos"));
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);

        User userDetails = (User) authentication.getPrincipal();
        ResponseCookie jwtCookie = jwtUtil.generateJwtCookie(userDetails);
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString()).body(userDetails);
    }

    public ResponseEntity<?> register(RegistrationRequest request) {
        if (userRepository.existsByEmail(request.getEmail()))
            return ResponseEntity.badRequest().body(new MessageResponse("Error: El email ya está registrado"));

        if (!emailValidator.test(request.getEmail()))
            return ResponseEntity.badRequest().body(new MessageResponse("Error: El email no es válido"));

        User user = new User(request.getFirstName(),
                request.getLastName(),
                request.getEmail(),
                bCryptPasswordEncoder.encode(request.getPassword()),
                UserRole.ROLE_USER);
        userRepository.save(user);

        String token = UUID.randomUUID().toString();
        ConfirmationToken confirmationToken = new ConfirmationToken(token, LocalDateTime.now(), LocalDateTime.now().plusMinutes(15), user);
        confirmationTokenService.saveConfirmationToken(confirmationToken);

        String link = "http://localhost:8080/api/v1/auth/signup/confirm?token=" + token;
        emailSender.send(request.getEmail(), buildEmail(request.getFirstName(), link));

        return ResponseEntity.ok(new MessageResponse("Te has registrado correctamente. Por favor, revisa tu email para confirmar tu cuenta. " + token));
    }

    public ResponseEntity<?> logoutUser() {
        ResponseCookie cookie = jwtUtil.getCleanJwtCookie();
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(new MessageResponse("Has cerrado sesión correctamente"));
    }

    public String resetPasswordToken(User user) {
        String token = UUID.randomUUID().toString();
        ConfirmationToken confirmationToken = new ConfirmationToken(token, LocalDateTime.now(), LocalDateTime.now().plusMinutes(15), user);

        confirmationTokenService.saveConfirmationToken(confirmationToken);
        //TODO: send email.
        return token;
    }

    public void updatePassword(String password, String email) {
        String encodedPassword = bCryptPasswordEncoder.encode(password);
        userRepository.updatePassword(encodedPassword, email);
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
        userRepository.enableUser(confirmationToken.getUser().getEmail());

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
