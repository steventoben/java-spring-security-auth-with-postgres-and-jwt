package com.example.spx.exception;

public class AuthException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    public AuthException(String msg) {
        super(msg);
    }
}
