package com.albarez.login.payload.response;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.util.List;

public class UserInfoResponse {

    private String firstName;
    private String lastName;
    private String email;
    private List<String> roles;

    public UserInfoResponse( String firstName, String lastName, String email, List<String> roles) {

        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
        this.roles = roles;
    }




    public String getFirstName() {
        return firstName;
    }


    public String getLastName() {
        return lastName;
    }


    public String getEmail() {
        return email;
    }


    public List<String> getRoles() {
        return roles;
    }


}


