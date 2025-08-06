package com.example.demoOAuth.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.Builder;

import java.util.List;

@Data
@Builder
public class BulkUserRegistrationRequest {
    
    @Valid
    @NotEmpty(message = "User list cannot be empty")
    @Size(max = 100, message = "Maximum 100 users can be registered at once")
    private List<UserRegistrationRequest> users;
    
    @Builder.Default
    private Boolean skipDuplicates = false; // Skip existing users vs fail
    
    @Builder.Default
    private Boolean dryRun = false; // Validate only, don't create
}
