package com.example.spx.dto;

import lombok.Data;

@Data
public class AuthenticationRequestBody {
    private String username;
    private String password;
}
