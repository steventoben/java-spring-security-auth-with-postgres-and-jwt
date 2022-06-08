package com.example.spx.constants;

//Class is final to prevent extensions
public final class SecurityConstants {
    //JWTs expire 36000 seconds (10 hours) after being issued
    public static final long JWT_EXPIRES_IN_SECONDS = 36000L;
    //Default strength of hashing algorithm.
    public static final int BCRYPT_HASHING_STRENGTH = 10;
    //private constructor so this class can not be instantiated
    private SecurityConstants() {

    }
}
