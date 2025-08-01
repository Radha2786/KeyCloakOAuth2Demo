package com.example.demoOAuth.controller;

import com.example.demoOAuth.dto.*;
import com.example.demoOAuth.entity.User;
import com.example.demoOAuth.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Slf4j
public class UserController {
    
    private final UserService userService;
    
    /**
     * Public endpoint for user registration
     */
    @PostMapping("/register")
    public ResponseEntity<UserRegistrationResponse> registerUser(@Valid @RequestBody UserRegistrationRequest request) {
        log.info("Registration request received for username: {}", request.getUsername());
        
        UserRegistrationResponse response = userService.registerUser(request);
        
        if (response.isSuccess()) {
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }
    
    /**
     * Public endpoint for user login
     */
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> loginUser(@Valid @RequestBody LoginRequest request) {
        log.info("Login request received for username: {}", request.getUsername());
        
        LoginResponse response = userService.authenticateUser(request);
        
        if (response.isSuccess()) {
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }
    
    /**
     * Public endpoint for token refresh
     */
    @PostMapping("/refresh-token")
    public ResponseEntity<LoginResponse> refreshToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        
        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            return ResponseEntity.badRequest()
                .body(LoginResponse.error("Refresh token is required"));
        }
        
        LoginResponse response = userService.refreshUserToken(refreshToken);
        
        if (response.isSuccess()) {
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }
    
    /**
     * Protected endpoint - get current user profile
     * Requires valid JWT token
     */
    @GetMapping("/profile")
    @PreAuthorize("hasAuthority('SCOPE_profile')")
    public ResponseEntity<?> getUserProfile(Authentication authentication) {
        try {
            if (authentication.getPrincipal() instanceof Jwt jwt) {
                String username = jwt.getClaimAsString("preferred_username");
                
                if (username != null) {
                    Optional<User> userOpt = userService.getUserByUsername(username);
                    
                    if (userOpt.isPresent()) {
                        User user = userOpt.get();
                        
                        // Create a safe response without sensitive data
                        Map<String, Object> userProfile = Map.of(
                            "id", user.getId(),
                            "username", user.getUsername(),
                            "email", user.getEmail(),
                            "firstName", user.getFirstName(),
                            "lastName", user.getLastName(),
                            "enabled", user.getEnabled(),
                            "createdAt", user.getCreatedAt()
                        );
                        
                        return ResponseEntity.ok(userProfile);
                    } else {
                        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                            .body(Map.of("error", "User not found in local database"));
                    }
                } else {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of("error", "Username not found in token"));
                }
            } else {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "Invalid token format"));
            }
            
        } catch (Exception e) {
            log.error("Error getting user profile", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Internal server error"));
        }
    }
    
    /**
     * Protected endpoint - admin only
     * Requires admin role
     */
    @GetMapping("/admin/users")
    @PreAuthorize("hasRole('admin')")
    public ResponseEntity<?> getAllUsers(Authentication authentication) {
        try {
            // This is just an example - implement according to your needs
            return ResponseEntity.ok(Map.of(
                "message", "Admin endpoint accessed successfully",
                "user", authentication.getName()
            ));
            
        } catch (Exception e) {
            log.error("Error in admin endpoint", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Internal server error"));
        }
    }
    
    /**
     * Health check endpoint
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> healthCheck() {
        return ResponseEntity.ok(Map.of(
            "status", "UP",
            "service", "User Service",
            "timestamp", java.time.Instant.now().toString()
        ));
    }
}