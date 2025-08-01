package com.example.demoOAuth.dto;

import lombok.Data;

@Data
public class LoginResponse {
    private String accessToken;
    private String refreshToken;
    private String tokenType;
    private int expiresIn;
    private String scope;
    private boolean success;
    private String message;
    
    public LoginResponse(String accessToken, String refreshToken, String tokenType, 
                        int expiresIn, String scope, boolean success, String message) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.tokenType = tokenType;
        this.expiresIn = expiresIn;
        this.scope = scope;
        this.success = success;
        this.message = message;
    }
    
    public static LoginResponse success(String accessToken, String refreshToken, String tokenType, 
                                      int expiresIn, String scope) {
        return new LoginResponse(accessToken, refreshToken, tokenType, expiresIn, scope, true, "Login successful");
    }
    
    public static LoginResponse error(String message) {
        return new LoginResponse(null, null, null, 0, null, false, message);
    }
}
