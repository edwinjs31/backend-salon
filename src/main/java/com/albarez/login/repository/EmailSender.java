package com.albarez.login.repository;

public interface EmailSender {
    void send(String to, String email);
}
