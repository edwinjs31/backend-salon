package com.albarez.login.service;

import org.springframework.stereotype.Service;

import java.util.function.Predicate;

@Service
public class EmailValidator implements Predicate <String> {

    //TODO: Regex email
   /* private static final String EMAIL_PATTERN = "^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@"
            + "[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$";*/

    @Override
    public boolean test(String email) {
        //return email.matches(EMAIL_PATTERN);
        return true;
    }

}
