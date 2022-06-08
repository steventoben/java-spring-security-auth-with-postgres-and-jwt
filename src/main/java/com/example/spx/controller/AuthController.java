package com.example.spx.controller;

import com.example.spx.dto.AuthenticationResponseBody;
import com.example.spx.dto.CreateUserDTO;
import com.example.spx.dto.UserCredentialsDTO;
import com.example.spx.exception.UserDoesNotExistException;
import com.example.spx.exception.UsernameNotAvailableException;
import com.example.spx.model.User;
import com.example.spx.repository.UserRepository;
import com.example.spx.service.UserAuthenticationService;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.web.bind.annotation.*;

@Data
@RestController
public class AuthController {

    @Autowired
    private JwtEncoder jwtEncoder;

    @Autowired
    UserAuthenticationService userAuthenticationService;

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping(path = "login")
    public AuthenticationResponseBody login(@RequestBody UserCredentialsDTO requestBody) throws Exception {
        User user = userRepository.findUserByUsername(requestBody.getUsername());

        if(user == null) {
            throw new UserDoesNotExistException("User not found");
        }

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(requestBody.getUsername(), requestBody.getPassword());

        Authentication authenticationResult = authenticationManager.authenticate(token);

        SecurityContextHolder.getContext().setAuthentication(authenticationResult);

        if(authenticationResult.isAuthenticated()) {
            System.out.println("User is authenticated!!");
        }
        String authToken = userAuthenticationService.getToken(authenticationResult);
        return new AuthenticationResponseBody(authenticationResult.isAuthenticated(), authToken);

    }


    @GetMapping(path = "test")
    public String getTestAuth(Authentication authentication) {
        return authentication.getName();
    }

    @ResponseStatus(code = HttpStatus.CREATED)
    @PostMapping("create")
    public void createUser(@RequestBody CreateUserDTO userDto) throws Exception {
        User existingUser = userRepository.findUserByUsername(userDto.getUsername());
        if(existingUser != null) {
            throw new UsernameNotAvailableException("Username taken");
        }
        User user = new User();
        user.setUsername(userDto.getUsername());
        user.setPassword(this.passwordEncoder.encode(userDto.getPassword()));
        this.userRepository.save(user);
    }
}
