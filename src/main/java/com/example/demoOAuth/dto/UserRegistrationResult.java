package com.example.demoOAuth.dto;

import lombok.Data;
import lombok.Builder;

@Data
@Builder
public class UserRegistrationResult {
    private String username;
    private String email;
    private Boolean success;
    private String message;
    private String userId; // Local database ID if successful
}
