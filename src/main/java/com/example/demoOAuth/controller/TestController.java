package com.example.demoOAuth.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/test")
public class TestController {
    
    @GetMapping("/public")
    public Map<String, Object> publicEndpoint() {
        return Map.of(
            "message", "This is a public endpoint",
            "timestamp", java.time.Instant.now().toString(),
            "access", "public"
        );
    }
    
    @GetMapping("/protected")
    @PreAuthorize("hasAuthority('SCOPE_profile')")
    public Map<String, Object> protectedEndpoint(Authentication authentication) {
        return Map.of(
            "message", "This is a protected endpoint",
            "user", authentication.getName(),
            "authorities", authentication.getAuthorities(),
            "timestamp", java.time.Instant.now().toString(),
            "access", "protected"
        );
    }
    
    @GetMapping("/admin")
    @PreAuthorize("hasRole('admin')")
    public Map<String, Object> adminEndpoint(Authentication authentication) {
        return Map.of(
            "message", "This is an admin endpoint",
            "user", authentication.getName(),
            "authorities", authentication.getAuthorities(),
            "timestamp", java.time.Instant.now().toString(),
            "access", "admin"
        );
    }
}
