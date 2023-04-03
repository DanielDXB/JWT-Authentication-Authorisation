package com.dxb.security.auth;

import com.dxb.security.config.JwtService;
import com.dxb.security.user.Role;
import com.dxb.security.user.UserModel;
import com.dxb.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    public AuthenticationResponse register(RegisterRequest registerRequest) {
        var user = UserModel.builder()
                .userFullName(registerRequest.getUserFullName())
                .userEmail(registerRequest.getUserEmail())
                .userPassword(passwordEncoder.encode(registerRequest.getUserPassword()))
                .role(Role.USER)
                .build();
        this.userRepository.save(user);
        var jwtToken = this.jwtService.generateJwtToken(user);
        return AuthenticationResponse.builder()
                .jwtToken(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
        this.authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authenticationRequest.getUserEmail(),
                        authenticationRequest.getUserPassword()
                )
        );
        var user = this.userRepository.findByUserEmail(authenticationRequest.getUserEmail())
                .orElseThrow();
        var jwtToken = this.jwtService.generateJwtToken(user);
        return AuthenticationResponse.builder()
                .jwtToken(jwtToken)
                .build();
    }
}
