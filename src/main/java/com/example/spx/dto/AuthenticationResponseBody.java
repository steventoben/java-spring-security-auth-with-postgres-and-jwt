package com.example.spx.dto;

public class AuthenticationResponseBody {
    private final Boolean authenticated;
    private final String token;
    public AuthenticationResponseBody(Boolean authenticated, String token) {
        this.authenticated = authenticated;
        this.token = token;
    }
    public Boolean getAuthenticated() {
        return authenticated;
    }
    public String getToken() {
        return token;
    }
}
