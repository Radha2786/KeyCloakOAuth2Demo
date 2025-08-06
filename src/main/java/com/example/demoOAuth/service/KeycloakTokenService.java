package com.example.demoOAuth.service;

import com.example.demoOAuth.dto.LoginRequest;
import com.example.demoOAuth.dto.LoginResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
@Slf4j
public class KeycloakTokenService {
    
    @Value("${keycloak.token.server-url}")
    private String serverUrl;
    
    @Value("${keycloak.token.realm}")
    private String realm;
    
    @Value("${keycloak.token.client-id}")
    private String clientId;
    
    @Value("${keycloak.token.client-secret}")
    private String clientSecret;
    
    private final RestTemplate restTemplate;
    
    public KeycloakTokenService() {
        this.restTemplate = new RestTemplate();
    }
    
    /**
     * Authenticate user and get access token
     */
    public LoginResponse authenticateUser(LoginRequest loginRequest) {
        try {
            String tokenUrl = serverUrl + "/realms/" + realm + "/protocol/openid-connect/token";
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "password");
            body.add("client_id", clientId);
            body.add("client_secret", clientSecret);
            body.add("username", loginRequest.getUsername());
            body.add("password", loginRequest.getPassword());
            body.add("scope", "openid profile email");
            
            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
            
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                tokenUrl,
                HttpMethod.POST,
                request,
                new ParameterizedTypeReference<Map<String, Object>>() {}
            );
            
            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map<String, Object> tokenData = response.getBody();
                
                String accessToken = (String) tokenData.get("access_token");
                String refreshToken = (String) tokenData.get("refresh_token");
                String tokenType = (String) tokenData.get("token_type");
                Integer expiresIn = (Integer) tokenData.get("expires_in");
                String scope = (String) tokenData.get("scope");
                
                log.info("User {} authenticated successfully", loginRequest.getUsername());
                
                return LoginResponse.success(
                    accessToken,
                    refreshToken,
                    tokenType != null ? tokenType : "Bearer",
                    expiresIn != null ? expiresIn : 0,
                    scope
                );
            }
            
            log.error("Authentication failed for user: {}. Status: {}", 
                     loginRequest.getUsername(), response.getStatusCode());
            return LoginResponse.error("Authentication failed");
            
        } catch (Exception e) {
            log.error("Error authenticating user: {}", loginRequest.getUsername(), e);
            return LoginResponse.error("Authentication error: " + e.getMessage());
        }
    }
    
    /**
     * Refresh access token using refresh token
     */
    public LoginResponse refreshToken(String refreshToken) {
        try {
            String tokenUrl = serverUrl + "/realms/" + realm + "/protocol/openid-connect/token";
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "refresh_token");
            body.add("client_id", clientId);
            body.add("client_secret", clientSecret);
            body.add("refresh_token", refreshToken);
            
            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
            
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                tokenUrl,
                HttpMethod.POST,
                request,
                new ParameterizedTypeReference<Map<String, Object>>() {}
            );
            
            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map<String, Object> tokenData = response.getBody();
                
                String accessToken = (String) tokenData.get("access_token");
                String newRefreshToken = (String) tokenData.get("refresh_token");
                String tokenType = (String) tokenData.get("token_type");
                Integer expiresIn = (Integer) tokenData.get("expires_in");
                String scope = (String) tokenData.get("scope");
                
                log.info("Token refreshed successfully");
                
                return LoginResponse.success(
                    accessToken,
                    newRefreshToken,
                    tokenType != null ? tokenType : "Bearer",
                    expiresIn != null ? expiresIn : 0,
                    scope
                );
            }
            
            log.error("Token refresh failed. Status: {}", response.getStatusCode());
            return LoginResponse.error("Token refresh failed");
            
        } catch (Exception e) {
            log.error("Error refreshing token", e);
            return LoginResponse.error("Token refresh error: " + e.getMessage());
        }
    }
}
