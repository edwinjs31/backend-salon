package com.albarez.login.service;

import com.albarez.login.model.Role;
import com.albarez.login.model.User;
import com.albarez.login.model.UserRole;
import com.albarez.login.payload.response.UserInfoResponse;
import com.albarez.login.repository.RoleRepository;
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
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
@AllArgsConstructor
public class UserService {

    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    UserRepository userRepository;
    @Autowired
    RoleRepository roleRepository;
    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;
    @Autowired
    EmailValidator emailValidator;
    @Autowired
    ConfirmationTokenService confirmationTokenService;
    @Autowired
    EmailSender emailSender;
    @Autowired
    JwtUtil jwtUtil;


    public ResponseEntity<?> authenticateUser(String email, String password) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
        if (!authentication.isAuthenticated()) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Usuario o contraseña incorrectos"));
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        ResponseCookie jwtCookie = jwtUtil.generateJwtCookie(userDetails);
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).toList();

        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                .body(new UserInfoResponse( userDetails.getFirstName(),userDetails.getLastName(),userDetails.getEmail(), roles));
    }

    public ResponseEntity<?> register(RegistrationRequest registrationRequest) {
        if (userRepository.existsByEmail(registrationRequest.getEmail()))
            return ResponseEntity.badRequest().body(new MessageResponse("Error: El email ya está registrado"));

        if (!emailValidator.test(registrationRequest.getEmail()))
            return ResponseEntity.badRequest().body(new MessageResponse("Error: El email no es válido"));

        //Se crea el usuario
        User user = new User(registrationRequest.getFirstName(),
                registrationRequest.getLastName(),
                registrationRequest.getEmail(),
                bCryptPasswordEncoder.encode(registrationRequest.getPassword()));
        Set<String> userRoles = registrationRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (userRoles == null) {
            Role userRole = roleRepository.findByName(UserRole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            userRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(UserRole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "super":
                        Role modRole = roleRepository.findByName(UserRole.ROLE_SUPER_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(UserRole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }
        //Se guarda el usuario en la base de datos
        user.setRoles(roles);
        userRepository.save(user);

        //Se crea el token de confirmación y se envía por correo
        String token = UUID.randomUUID().toString();
        ConfirmationToken confirmationToken = new ConfirmationToken(token, LocalDateTime.now(), LocalDateTime.now().plusMinutes(15), user);
        confirmationTokenService.saveConfirmationToken(confirmationToken);
        String link = "http://localhost:8080/api/v1/auth/signup/confirm?token=" + token;
        emailSender.send(registrationRequest.getEmail(), buildEmail(registrationRequest.getFirstName(), link));

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
