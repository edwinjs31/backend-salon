package com.albarez.login.service;

import com.albarez.login.model.User;
import com.albarez.login.request.LoginRequest;
import com.albarez.login.security.jwt.JwtUtil;
import com.albarez.login.security.token.ConfirmationToken;
import com.albarez.login.repository.UserRepository;
import com.albarez.login.security.token.ConfirmationTokenService;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@AllArgsConstructor
public class MyUserDetailsService implements UserDetailsService {

    private final static String USER_NOT_FOUND_MSG = "Usuario con email %s no encontrado";
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final ConfirmationTokenService confirmationTokenService;
    private final JwtUtil jwtUtil;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException(String.format(USER_NOT_FOUND_MSG, email)));
    }

    public ResponseEntity<?> singin(LoginRequest request) {
        User userFound = userRepository.findByEmail(request.getEmail()).orElseThrow(() -> new UsernameNotFoundException(String.format(USER_NOT_FOUND_MSG, request.getEmail())));

        if (userFound.isEnabled()) {
            if (bCryptPasswordEncoder.matches(request.getPassword(), userFound.getPassword())) {
                String token = jwtUtil.getJWTToken(userFound.getEmail());
                userFound.setJwtToken(token);
                userRepository.updateJwtToken(token, userFound.getEmail());
                return ResponseEntity.ok(token);
            } else {
                return ResponseEntity.badRequest().body("Contraseña incorrecta");
            }
        } else {
            return ResponseEntity.badRequest().body("Usuario no ha sido confirmado");
        }
    }

    //Registro de usuario
    public String singUpUser(User user) {

        boolean isUserExist = userRepository.findByEmail(user.getEmail()).isPresent();

        if (isUserExist) {
            //TODO verificacion de atributos e la misma y confirmar el correo.
            throw new IllegalStateException("Usuario con email " + user.getEmail() + " ya existe");
        }

        String encodedPassword = bCryptPasswordEncoder.encode(user.getPassword());
        user.setPassword(encodedPassword);
        userRepository.save(user);

        String token = UUID.randomUUID().toString();
        ConfirmationToken confirmationToken = new ConfirmationToken(token, LocalDateTime.now(), LocalDateTime.now().plusMinutes(15), user);

        confirmationTokenService.saveConfirmationToken(confirmationToken);
        //TODO: send email.
        return token;
    }

    //Confirmacion de registro y modifica a activado
    public void enableUser(String email) {
        userRepository.enableUser(email);
    }

    //recuperacion de contraseña.
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


}
