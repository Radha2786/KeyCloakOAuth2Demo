package com.example.demoOAuth.service;

import com.example.demoOAuth.dto.LoginRequest;
import com.example.demoOAuth.dto.LoginResponse;
import com.example.demoOAuth.dto.UserRegistrationRequest;
import com.example.demoOAuth.dto.UserRegistrationResponse;
import com.example.demoOAuth.entity.User;
import com.example.demoOAuth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {
    
    private final UserRepository userRepository;
    private final KeycloakAdminService keycloakAdminService;
    private final KeycloakTokenService keycloakTokenService;
    
    /**
     * Register a new user in both local database and Keycloak
     */
    @Transactional
    public UserRegistrationResponse registerUser(UserRegistrationRequest request) {
        try {
            // Check if user already exists in local database
            if (userRepository.existsByUsername(request.getUsername())) {
                log.warn("Registration failed: Username {} already exists in local database", request.getUsername());
                return UserRegistrationResponse.error("Username already exists");
            }
            
            if (userRepository.existsByEmail(request.getEmail())) {
                log.warn("Registration failed: Email {} already exists in local database", request.getEmail());
                return UserRegistrationResponse.error("Email already exists");
            }
            
            // Check if user exists in Keycloak
            if (keycloakAdminService.userExistsInKeycloak(request.getUsername())) {
                log.warn("Registration failed: Username {} already exists in Keycloak", request.getUsername());
                return UserRegistrationResponse.error("Username already exists in authentication system");
            }
            
            // Create user in Keycloak first
            String keycloakUserId = keycloakAdminService.createKeycloakUser(
                request.getUsername(),
                request.getEmail(),
                request.getFirstName(),
                request.getLastName(),
                request.getPassword()
            );
            
            if (keycloakUserId == null) {
                log.error("Failed to create user in Keycloak for username: {}", request.getUsername());
                return UserRegistrationResponse.error("Failed to create user in authentication system");
            }
            
            // Create user in local database
            User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .keycloakUserId(keycloakUserId)
                .enabled(true)
                .build();
            
            User savedUser = userRepository.save(user);
            
            log.info("User registered successfully: username={}, id={}, keycloakId={}", 
                    savedUser.getUsername(), savedUser.getId(), keycloakUserId);
            
            return UserRegistrationResponse.success(savedUser.getId().toString());
            
        } catch (Exception e) {
            log.error("Error during user registration for username: {}", request.getUsername(), e);
            return UserRegistrationResponse.error("Registration failed: " + e.getMessage());
        }
    }
    
    /**
     * Authenticate user using Keycloak
     */
    public LoginResponse authenticateUser(LoginRequest loginRequest) {
        try {
            // Check if user exists in local database
            Optional<User> userOpt = userRepository.findByUsername(loginRequest.getUsername());
            if (userOpt.isEmpty()) {
                log.warn("Login failed: User {} not found in local database", loginRequest.getUsername());
                return LoginResponse.error("User not found");
            }
            
            User user = userOpt.get();
            if (!user.getEnabled()) {
                log.warn("Login failed: User {} is disabled", loginRequest.getUsername());
                return LoginResponse.error("User account is disabled");
            }
            
            // Authenticate with Keycloak
            LoginResponse response = keycloakTokenService.authenticateUser(loginRequest);
            
            if (response.isSuccess()) {
                log.info("User {} authenticated successfully", loginRequest.getUsername());
            } else {
                log.warn("Authentication failed for user: {}", loginRequest.getUsername());
            }
            
            return response;
            
        } catch (Exception e) {
            log.error("Error during authentication for user: {}", loginRequest.getUsername(), e);
            return LoginResponse.error("Authentication error: " + e.getMessage());
        }
    }
    
    /**
     * Refresh user token
     */
    public LoginResponse refreshUserToken(String refreshToken) {
        return keycloakTokenService.refreshToken(refreshToken);
    }
    
    /**
     * Get user by username
     */
    public Optional<User> getUserByUsername(String username) {
        return userRepository.findByUsername(username);
    }
    
    /**
     * Get user by email
     */
    public Optional<User> getUserByEmail(String email) {
        return userRepository.findByEmail(email);
    }
    
    /**
     * Get user by Keycloak user ID
     */
    public Optional<User> getUserByKeycloakId(String keycloakUserId) {
        return userRepository.findByKeycloakUserId(keycloakUserId);
    }
}
