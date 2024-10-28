package com.example.springsecurityjwt;

import org.springframework.security.core.Authentication;import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController

public class AuthenticationController {
    private final AuthenticationService authenticationService ;// injeção de dependência

    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("authenticate")
    public String authenticate(Authentication authentication) {
        return authenticationService.authenticate(authentication);
    }
}
