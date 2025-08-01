package com.example.demoOAuth.dto;

import lombok.Data;

@Data
public class UserRegistrationResponse {
    private String message;
    private String userId;
    private boolean success;
    
    public UserRegistrationResponse(String message, String userId, boolean success) {
        this.message = message;
        this.userId = userId;
        this.success = success;
    }
    
    public static UserRegistrationResponse success(String userId) {
        return new UserRegistrationResponse("User registered successfully", userId, true);
    }
    
    public static UserRegistrationResponse error(String message) {
        return new UserRegistrationResponse(message, null, false);
    }
}
