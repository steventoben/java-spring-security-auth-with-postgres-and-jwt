package com.example.spx.exception;

public class UsernameNotAvailableException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    public UsernameNotAvailableException(String msg) {
        super(msg);
    }
}
