package com.example.spx.exception;

public class UserDoesNotExistException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    public UserDoesNotExistException(String msg) {
        super(msg);
    }
}
