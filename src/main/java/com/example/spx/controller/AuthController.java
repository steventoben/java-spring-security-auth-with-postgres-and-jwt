package com.example.spx.controller;

import com.example.spx.dto.AuthenticationRequestBody;
import com.example.spx.dto.AuthenticationResponseBody;
import com.example.spx.dto.CreateUserDTO;
import com.example.spx.model.User;
import com.example.spx.repository.UserRepository;
import com.example.spx.service.UserAuthenticationService;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.time.Instant;
import java.util.stream.Collectors;

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
    public AuthenticationResponseBody login(@RequestBody AuthenticationRequestBody requestBody) throws Exception {
        User user = userRepository.findUserByUsername(requestBody.getUsername());
        System.out.println("Provided username: " + requestBody.getUsername() + " , Provided password: " + requestBody.getPassword());

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(requestBody.getUsername(), requestBody.getPassword());

        System.out.println("Auth token before authentication logic: " + token);

        Authentication authenticationResult = authenticationManager.authenticate(token);

        System.out.println("Auth token after authentication logic: " + authenticationResult);
        System.out.println("Auth token in Security Context: " + SecurityContextHolder.getContext().getAuthentication());
        SecurityContextHolder.getContext().setAuthentication(authenticationResult);

        if(authenticationResult.isAuthenticated()) {
            System.out.println("User is authenticated!!");
        }
        String authToken = token(authenticationResult);
        return new AuthenticationResponseBody(authenticationResult.isAuthenticated(), authToken);

        /*boolean match = passwordEncoder.matches(user.getPassword(), userDto.getPassword());
        if(match == false) {
            throw new Exception("Hashed raw password and stored hash Do not match");
        }
        return user.getUsername();*/
    }

    @RequestMapping("/user")
    public Principal userPrincipal(Principal user) {
        return user;
    }

    @PostMapping(path = "token")
    public String token(Authentication authentication) {
        return userAuthenticationService.getToken(authentication);
        /*Instant now = Instant.now();
        long expiry = 36000L;
        String scope = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));
        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(expiry))
                .subject(authentication.getName())
                .claim("scope", scope)
                .build();
        return this.jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();*/
    }

    @GetMapping(path = "test")
    public String getTestAuth(Authentication authentication) {
        return authentication.getName();
    }

    @PostMapping("create")
    public void createUser(@RequestBody CreateUserDTO userDto) {
        /*System.out.println(this.passwordEncoder.encode("myPassword"));
        System.out.println(userDto.getUsername());
        System.out.println(userDto.getPassword());
        User user = new User();
        user.setUsername(userDto.getUsername());
        user.setPassword(this.passwordEncoder.encode(userDto.getPassword()));
        this.userRepository.save(user);*/
        User newUser = userAuthenticationService.createUser(userDto);
        System.out.println("User created: " + newUser);
    }
}
