package com.example.demoOAuth.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@Slf4j
public class KeycloakAdminService {
    
    @Value("${keycloak.admin.server-url}")
    private String serverUrl;
    
    @Value("${keycloak.admin.realm}")
    private String realm;
    
    @Value("${keycloak.admin.client-id}")
    private String clientId;
    
    @Value("${keycloak.admin.client-secret}")
    private String clientSecret;
    
    @Value("${keycloak.admin.username}")
    private String adminUsername;
    
    @Value("${keycloak.admin.password}")
    private String adminPassword;
    
    private final RestTemplate restTemplate;
    
    public KeycloakAdminService() {
        this.restTemplate = new RestTemplate();
    }
    
    /**
     * Get admin access token to call Keycloak Admin API
     */
    public String getAdminAccessToken() {
        try {
            String tokenUrl = serverUrl + "/realms/master/protocol/openid-connect/token";
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "password");
            body.add("client_id", "admin-cli");
            body.add("username", adminUsername);
            body.add("password", adminPassword);
            
            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
            
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                tokenUrl, 
                HttpMethod.POST, 
                request, 
                new ParameterizedTypeReference<Map<String, Object>>() {}
            );
            
            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                return (String) response.getBody().get("access_token");
            }
            
            log.error("Failed to get admin access token. Status: {}", response.getStatusCode());
            return null;
            
        } catch (Exception e) {
            log.error("Error getting admin access token", e);
            return null;
        }
    }
    
    /**
     * Create a new user in Keycloak
     */
    public String createKeycloakUser(String username, String email, String firstName, 
                                   String lastName, String password) {
        try {
            String accessToken = getAdminAccessToken();
            if (accessToken == null) {
                log.error("Cannot create user: Failed to get admin access token");
                return null;
            }
            
            String createUserUrl = serverUrl + "/admin/realms/" + realm + "/users";
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(accessToken);
            
            // Create user representation
            Map<String, Object> userRepresentation = new HashMap<>();
            userRepresentation.put("username", username);
            userRepresentation.put("email", email);
            userRepresentation.put("firstName", firstName);
            userRepresentation.put("lastName", lastName);
            userRepresentation.put("enabled", true);
            userRepresentation.put("emailVerified", true);
            
            // Set password
            Map<String, Object> credential = new HashMap<>();
            credential.put("type", "password");
            credential.put("value", password);
            credential.put("temporary", false);
            userRepresentation.put("credentials", List.of(credential));
            
            HttpEntity<Map<String, Object>> request = new HttpEntity<>(userRepresentation, headers);
            
            ResponseEntity<String> response = restTemplate.postForEntity(createUserUrl, request, String.class);
            
            if (response.getStatusCode() == HttpStatus.CREATED) {
                // Extract user ID from Location header
                String locationHeader = response.getHeaders().getFirst("Location");
                if (locationHeader != null) {
                    String userId = locationHeader.substring(locationHeader.lastIndexOf("/") + 1);
                    log.info("User created successfully in Keycloak with ID: {}", userId);
                    return userId;
                }
            }
            
            log.error("Failed to create user in Keycloak. Status: {}, Body: {}", 
                     response.getStatusCode(), response.getBody());
            return null;
            
        } catch (Exception e) {
            log.error("Error creating user in Keycloak", e);
            return null;
        }
    }
    
    /**
     * Check if user exists in Keycloak by username
     */
    public boolean userExistsInKeycloak(String username) {
        try {
            String accessToken = getAdminAccessToken();
            if (accessToken == null) {
                return false;
            }
            
            String searchUrl = serverUrl + "/admin/realms/" + realm + "/users?username=" + username;
            
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            
            HttpEntity<String> request = new HttpEntity<>(headers);
            
            ResponseEntity<List<Map<String, Object>>> response = restTemplate.exchange(
                searchUrl, 
                HttpMethod.GET, 
                request, 
                new ParameterizedTypeReference<List<Map<String, Object>>>() {}
            );
            
            return response.getStatusCode() == HttpStatus.OK && 
                   response.getBody() != null && 
                   !response.getBody().isEmpty();
                   
        } catch (Exception e) {
            log.error("Error checking if user exists in Keycloak", e);
            return false;
        }
    }
    
    /**
     * Assign role to user in Keycloak
     */
    public boolean assignRoleToKeycloakUser(String keycloakUserId, String roleName) {
        try {
            String accessToken = getAdminAccessToken();
            if (accessToken == null) {
                log.error("Cannot assign role: Failed to get admin access token");
                return false;
            }
            
            // First, get the role representation
            String getRoleUrl = serverUrl + "/admin/realms/" + realm + "/roles/" + roleName;
            
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            
            HttpEntity<String> getRoleRequest = new HttpEntity<>(headers);
            
            ResponseEntity<Map<String, Object>> roleResponse = restTemplate.exchange(
                getRoleUrl,
                HttpMethod.GET,
                getRoleRequest,
                new ParameterizedTypeReference<Map<String, Object>>() {}
            );
            
            if (roleResponse.getStatusCode() != HttpStatus.OK || roleResponse.getBody() == null) {
                log.error("Role {} not found in Keycloak", roleName);
                return false;
            }
            
            // Assign role to user
            String assignRoleUrl = serverUrl + "/admin/realms/" + realm + "/users/" + keycloakUserId + "/role-mappings/realm";
            
            HttpHeaders assignHeaders = new HttpHeaders();
            assignHeaders.setContentType(MediaType.APPLICATION_JSON);
            assignHeaders.setBearerAuth(accessToken);
            
            List<Map<String, Object>> rolesToAssign = List.of(roleResponse.getBody());
            
            HttpEntity<List<Map<String, Object>>> assignRequest = new HttpEntity<>(rolesToAssign, assignHeaders);
            
            ResponseEntity<String> assignResponse = restTemplate.postForEntity(assignRoleUrl, assignRequest, String.class);
            
            if (assignResponse.getStatusCode() == HttpStatus.NO_CONTENT) {
                log.info("Successfully assigned role {} to user {} in Keycloak", roleName, keycloakUserId);
                return true;
            } else {
                log.error("Failed to assign role {} to user {} in Keycloak. Status: {}", 
                         roleName, keycloakUserId, assignResponse.getStatusCode());
                return false;
            }
            
        } catch (Exception e) {
            log.error("Error assigning role {} to user {} in Keycloak", roleName, keycloakUserId, e);
            return false;
        }
    }
    
    /**
     * Remove role from user in Keycloak
     */
    public boolean removeRoleFromKeycloakUser(String keycloakUserId, String roleName) {
        try {
            String accessToken = getAdminAccessToken();
            if (accessToken == null) {
                log.error("Cannot remove role: Failed to get admin access token");
                return false;
            }
            
            // First, get the role representation
            String getRoleUrl = serverUrl + "/admin/realms/" + realm + "/roles/" + roleName;
            
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            
            HttpEntity<String> getRoleRequest = new HttpEntity<>(headers);
            
            ResponseEntity<Map<String, Object>> roleResponse = restTemplate.exchange(
                getRoleUrl,
                HttpMethod.GET,
                getRoleRequest,
                new ParameterizedTypeReference<Map<String, Object>>() {}
            );
            
            if (roleResponse.getStatusCode() != HttpStatus.OK || roleResponse.getBody() == null) {
                log.error("Role {} not found in Keycloak", roleName);
                return false;
            }
            
            // Remove role from user
            String removeRoleUrl = serverUrl + "/admin/realms/" + realm + "/users/" + keycloakUserId + "/role-mappings/realm";
            
            HttpHeaders removeHeaders = new HttpHeaders();
            removeHeaders.setContentType(MediaType.APPLICATION_JSON);
            removeHeaders.setBearerAuth(accessToken);
            
            List<Map<String, Object>> rolesToRemove = List.of(roleResponse.getBody());
            
            HttpEntity<List<Map<String, Object>>> removeRequest = new HttpEntity<>(rolesToRemove, removeHeaders);
            
            ResponseEntity<String> removeResponse = restTemplate.exchange(removeRoleUrl, HttpMethod.DELETE, removeRequest, String.class);
            
            if (removeResponse.getStatusCode() == HttpStatus.NO_CONTENT) {
                log.info("Successfully removed role {} from user {} in Keycloak", roleName, keycloakUserId);
                return true;
            } else {
                log.error("Failed to remove role {} from user {} in Keycloak. Status: {}", 
                         roleName, keycloakUserId, removeResponse.getStatusCode());
                return false;
            }
            
        } catch (Exception e) {
            log.error("Error removing role {} from user {} in Keycloak", roleName, keycloakUserId, e);
            return false;
        }
    }
}
