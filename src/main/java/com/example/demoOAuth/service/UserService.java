package com.example.demoOAuth.service;

import com.example.demoOAuth.dto.*;
import com.example.demoOAuth.entity.User;
import com.example.demoOAuth.entity.UserRole;
import com.example.demoOAuth.helper.Helper;
import com.example.demoOAuth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {
    
    private final UserRepository userRepository;
    private final KeycloakAdminService keycloakAdminService;
    private final KeycloakTokenService keycloakTokenService;
    private final RoleService roleService;
    
    /**
     * Register a new user in both local database and Keycloak
     */
    @Transactional
    public UserRegistrationResponse registerUser(UserRegistrationRequest request) {
        try {
            // Validate role selection first
            roleService.validateRoleForRegistration(request.getRole());
            
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
            
            // Assign role in Keycloak
            boolean roleAssigned = keycloakAdminService.assignRoleToKeycloakUser(keycloakUserId, request.getRole());
            if (!roleAssigned) {
                log.error("Failed to assign role {} to user {} in Keycloak", request.getRole(), keycloakUserId);
                // Note: User is created in Keycloak but role assignment failed
                // In production, you might want to handle this differently
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
            
            // Assign role in local database
            roleService.assignRoleToUser(
                savedUser, 
                request.getRole(), 
                "SYSTEM", 
                UserRole.AssignmentMethod.SELF_REGISTRATION
            );
            
            log.info("User registered successfully: username={}, id={}, keycloakId={}, role={}", 
                    savedUser.getUsername(), savedUser.getId(), keycloakUserId, request.getRole());
            
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
    
    /**
     * Get user's roles from database
     */
    public List<String> getUserRoles(User user) {
        return roleService.getUserActiveRoles(user);
    }
    
    /**
     * Bulk register users from file
     */
    @Transactional
    public BulkUserRegistrationResponse bulkRegisterUsers(BulkUserRegistrationRequest request) {
        List<UserRegistrationResult> results = new ArrayList<>();
        List<String> globalErrors = new ArrayList<>();
        
        int successful = 0;
        int failed = 0;
        
        for (UserRegistrationRequest userRequest : request.getUsers()) {
            try {
                // Validate each user
                validateUserForBulkRegistration(userRequest);
                
                if (!request.getDryRun()) {
                    UserRegistrationResponse response = registerUser(userRequest);
                    
                    if (response.isSuccess()) {
                        results.add(UserRegistrationResult.builder()
                            .username(userRequest.getUsername())
                            .email(userRequest.getEmail())
                            .success(true)
                            .message("User registered successfully")
                            .userId(response.getUserId())
                            .build());
                        successful++;
                    } else {
                        if (request.getSkipDuplicates() && response.getMessage().contains("already exists")) {
                            results.add(UserRegistrationResult.builder()
                                .username(userRequest.getUsername())
                                .email(userRequest.getEmail())
                                .success(true)
                                .message("User already exists - skipped")
                                .build());
                            successful++;
                        } else {
                            results.add(UserRegistrationResult.builder()
                                .username(userRequest.getUsername())
                                .email(userRequest.getEmail())
                                .success(false)
                                .message(response.getMessage())
                                .build());
                            failed++;
                        }
                    }
                } else {
                    // Dry run - just validate
                    results.add(UserRegistrationResult.builder()
                        .username(userRequest.getUsername())
                        .email(userRequest.getEmail())
                        .success(true)
                        .message("Validation passed (dry run)")
                        .build());
                }
                
            } catch (Exception e) {
                results.add(UserRegistrationResult.builder()
                    .username(userRequest.getUsername())
                    .email(userRequest.getEmail())
                    .success(false)
                    .message("Registration failed: " + e.getMessage())
                    .build());
                failed++;
            }
        }
        
        return BulkUserRegistrationResponse.builder()
            .totalRequested(request.getUsers().size())
            .successfulRegistrations(successful)
            .failedRegistrations(failed)
            .results(results)
            .errors(globalErrors)
            .build();
    }
    
    /**
     * Parse user file and create bulk registration request
     */
    public BulkUserRegistrationRequest parseUserFile(MultipartFile file) throws IOException {
        List<UserRegistrationRequest> users = new ArrayList<>();
        
        try (InputStream inputStream = file.getInputStream()) {
            if (Helper.checkExcelFormat(file)) {
                users = Helper.convertExcelToListOfUserRegistrationRequest(inputStream);
            } else if (Helper.checkCSVFormat(file)) {
                users = Helper.convertCSVToListOfUserRegistrationRequest(inputStream);
            } else {
                throw new IllegalArgumentException("Unsupported file format. Please use .xlsx or .csv");
            }
        }
        
        return BulkUserRegistrationRequest.builder()
            .users(users)
            .skipDuplicates(true)
            .dryRun(false)
            .build();
    }
    
    /**
     * Validate user for bulk registration
     */
    private void validateUserForBulkRegistration(UserRegistrationRequest userRequest) {
        // Use existing role validation
        roleService.validateRoleForRegistration(userRequest.getRole());
        
        // Additional validations can be added here
        if (userRequest.getUsername() == null || userRequest.getUsername().trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be empty");
        }
        
        if (userRequest.getEmail() == null || userRequest.getEmail().trim().isEmpty()) {
            throw new IllegalArgumentException("Email cannot be empty");
        }
        
        if (userRequest.getPassword() == null || userRequest.getPassword().length() < 6) {
            throw new IllegalArgumentException("Password must be at least 6 characters");
        }
    }
    
    /**
     * Save users from file (existing method used by upload endpoint)
     */
    public BulkUserRegistrationResponse save(MultipartFile file) throws IOException {
        BulkUserRegistrationRequest request = parseUserFile(file);
        return bulkRegisterUsers(request);
    }
}
