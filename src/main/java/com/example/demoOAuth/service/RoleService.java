package com.example.demoOAuth.service;

import com.example.demoOAuth.entity.Role;
import com.example.demoOAuth.entity.User;
import com.example.demoOAuth.entity.UserRole;
import com.example.demoOAuth.repository.RoleRepository;
import com.example.demoOAuth.repository.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class RoleService implements CommandLineRunner {
    
    private final RoleRepository roleRepository;
    private final UserRoleRepository userRoleRepository;
    
    /**
     * Initialize default roles on application startup
     */
    @Override
    public void run(String... args) {
        initializeDefaultRoles();
    }
    
    @Transactional
    public void initializeDefaultRoles() {
        createRoleIfNotExists(Role.USER, "Default role for regular users", true);
        createRoleIfNotExists(Role.EMPLOYEE, "Role for company employees", true);
        createRoleIfNotExists(Role.ADMIN, "Administrative role with full access", false);
        
        log.info("Default roles initialized successfully");
    }
    
    private void createRoleIfNotExists(String roleName, String description, boolean isSelfAssignable) {
        if (!roleRepository.existsByName(roleName)) {
            Role role = Role.builder()
                .name(roleName)
                .description(description)
                .isSelfAssignable(isSelfAssignable)
                .build();
            
            roleRepository.save(role);
            log.info("Created role: {}", roleName);
        }
    }
    
    /**
     * Assign role to user
     */
    @Transactional
    public UserRole assignRoleToUser(User user, String roleName, String assignedBy, UserRole.AssignmentMethod method) {
        Optional<Role> roleOpt = roleRepository.findByName(roleName);
        if (roleOpt.isEmpty()) {
            throw new RuntimeException("Role not found: " + roleName);
        }
        
        Role role = roleOpt.get();
        
        // Check if user already has this role
        if (userRoleRepository.existsByUserAndRoleAndIsActiveTrue(user, role)) {
            log.warn("User {} already has role {}", user.getUsername(), roleName);
            return userRoleRepository.findByUserAndRoleAndIsActiveTrue(user, role).orElse(null);
        }
        
        UserRole userRole = UserRole.builder()
            .user(user)
            .role(role)
            .assignedBy(assignedBy)
            .assignmentMethod(method)
            .isActive(true)
            .build();
        
        UserRole savedUserRole = userRoleRepository.save(userRole);
        log.info("Assigned role {} to user {} by {} via {}", roleName, user.getUsername(), assignedBy, method);
        
        return savedUserRole;
    }
    
    /**
     * Check if role can be self-assigned
     */
    public boolean canSelfAssignRole(String roleName) {
        return roleRepository.findByName(roleName)
            .map(Role::getIsSelfAssignable)
            .orElse(false);
    }
    
    /**
     * Get user's active roles
     */
    public List<String> getUserActiveRoles(User user) {
        return userRoleRepository.findActiveRoleNamesByUser(user);
    }
    
    /**
     * Validate role assignment during registration
     */
    public void validateRoleForRegistration(String roleName) {
        if (Role.ADMIN.equals(roleName)) {
            throw new IllegalArgumentException("Admin role cannot be self-assigned during registration");
        }
        
        if (!canSelfAssignRole(roleName)) {
            throw new IllegalArgumentException("Role '" + roleName + "' cannot be self-assigned");
        }
    }
    
    /**
     * Get role by name
     */
    public Optional<Role> findRoleByName(String roleName) {
        return roleRepository.findByName(roleName);
    }
    
    /**
     * Remove role from user
     */
    @Transactional
    public void removeRoleFromUser(User user, String roleName) {
        Optional<Role> roleOpt = roleRepository.findByName(roleName);
        if (roleOpt.isPresent()) {
            Optional<UserRole> userRoleOpt = userRoleRepository.findByUserAndRoleAndIsActiveTrue(user, roleOpt.get());
            if (userRoleOpt.isPresent()) {
                UserRole userRole = userRoleOpt.get();
                userRole.setIsActive(false);
                userRoleRepository.save(userRole);
                log.info("Removed role {} from user {}", roleName, user.getUsername());
            }
        }
    }
}
