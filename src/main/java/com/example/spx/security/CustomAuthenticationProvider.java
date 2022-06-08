package com.example.spx.security;

import com.example.spx.exception.AuthException;
import com.example.spx.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    UserDetailsServiceImpl userDetailsService;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        System.out.println("Custom Auth Provider authenticate()");

        String username = authentication.getPrincipal().toString();
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        System.out.println("Provided username: " + username + " , userDetails from username: " + userDetails.toString());

        String password = authentication.getCredentials().toString();
        String hashedPassword = passwordEncoder.encode(password);
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder(10);
        String hashed = bCryptPasswordEncoder.encode(password);

        String realPassword = userDetails.getPassword();

        boolean passwordsMatch = passwordEncoder.matches(password, realPassword);

        System.out.println("Provided password: " + password + " , Hashed provided password: " + hashedPassword);
        System.out.println("Provided password: " + password + " , Test Hashing realtime: " + hashed);
        System.out.println("Provided password: " + password + " , Real password from userDetails: " + realPassword);
        System.out.println("Passwords match?: " + passwordsMatch);
        System.out.println("Passwords match test?: " + bCryptPasswordEncoder.matches(password, realPassword));
        System.out.println();
        System.out.println("Passwords match test? p: " + passwordEncoder.matches("myPassword", realPassword));
        System.out.println("Passwords match test? f: " + passwordEncoder.matches("myPasswor", realPassword));
        System.out.println("Passwords match test? p b: " + bCryptPasswordEncoder.matches("myPassword", realPassword));
        System.out.println("Passwords match test? f b: " + bCryptPasswordEncoder.matches("myPasswordd", realPassword));

        if(!passwordsMatch) {
            throw new AuthException("Password incorrect");
            //throw new RuntimeException("Passwords do not match");
        }
        /*if(!password.equals(realPassword)) {
            throw new RuntimeException("Passwords do not match");
        }*/

        Authentication authenticationResult = new UsernamePasswordAuthenticationToken(
                userDetails,
                authentication.getCredentials(),
                userDetails.getAuthorities()
        );


        return authenticationResult;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        System.out.println("Custom Auth Provider supports();");
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
