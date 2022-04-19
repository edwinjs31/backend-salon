package com.albarez.login.service;


import com.albarez.login.repository.UserRepository;

import lombok.AllArgsConstructor;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


@Service
@AllArgsConstructor
public class MyUserDetailsService implements UserDetailsService {

    private final static String USER_NOT_FOUND_MSG = "Usuario con email %s no encontrado";
    private final UserRepository userRepository;


    @Override
    @Transactional
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException(String.format(USER_NOT_FOUND_MSG, email)));
        //opcion 2
        //User user = userRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException(String.format(USER_NOT_FOUND_MSG, email)));
        //return user.build(user);
    }


    //opc1
    /*
    public ResponseEntity<?> authenticateUser(LoginRequest request) {
        User userFound = userRepository.findByEmail(request.getEmail()).orElseThrow(() -> new UsernameNotFoundException(String.format(USER_NOT_FOUND_MSG, request.getEmail())));

        if (userFound.isEnabled()) {
            if (bCryptPasswordEncoder.matches(request.getPassword(), userFound.getPassword())) {
                String token = jwtUtil.getJWTToken(userFound.getEmail());
                userFound.setJwtToken(token);
                userRepository.updateJwtToken(token, userFound.getEmail());
                return ResponseEntity.ok(userFound);
            } else {
                return ResponseEntity.badRequest().body("Contraseña incorrecta");
            }
        } else {
            return ResponseEntity.badRequest().body("Usuario no ha sido confirmado");
        }
    }*/

    //Confirmacion de registro y modifica a activado


    //recuperacion de contraseña.


}
