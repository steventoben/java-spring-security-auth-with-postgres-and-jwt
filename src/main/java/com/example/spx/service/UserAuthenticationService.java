package com.example.spx.service;

import com.example.spx.constants.SecurityConstants;
import com.example.spx.dto.CreateUserDTO;
import com.example.spx.model.User;
import com.example.spx.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.stream.Collectors;

@Service
public class UserAuthenticationService {

    @Autowired
    UserRepository userRepository;

    @Autowired
    JwtEncoder jwtEncoder;

    @Autowired
    PasswordEncoder passwordEncoder;

    public User createUser(CreateUserDTO createUserDTO) {

        User user = new User();
        user.setUsername(createUserDTO.getUsername());
        user.setPassword(passwordEncoder.encode(createUserDTO.getPassword()));
        return userRepository.save(user);
    }



    public String getToken(Authentication authentication) {
        Instant now = Instant.now();
        long expiresIn = SecurityConstants.JWT_EXPIRES_IN_SECONDS;
        String scope = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));
        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(expiresIn))
                .subject(authentication.getName())
                .claim("scope", scope)
                .build();
        return jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
    }
}
