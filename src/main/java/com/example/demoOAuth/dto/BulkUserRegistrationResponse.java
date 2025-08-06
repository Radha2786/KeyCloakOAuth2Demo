package com.example.demoOAuth.dto;

import lombok.Data;
import lombok.Builder;

import java.util.List;

@Data
@Builder
public class BulkUserRegistrationResponse {
    private Integer totalRequested;
    private Integer successfulRegistrations;
    private Integer failedRegistrations;
    private List<UserRegistrationResult> results;
    private List<String> errors;
    
    public static BulkUserRegistrationResponse success(Integer totalRequested, 
                                                      Integer successful, 
                                                      Integer failed,
                                                      List<UserRegistrationResult> results) {
        return BulkUserRegistrationResponse.builder()
            .totalRequested(totalRequested)
            .successfulRegistrations(successful)
            .failedRegistrations(failed)
            .results(results)
            .build();
    }
    
    public static BulkUserRegistrationResponse error(String errorMessage) {
        return BulkUserRegistrationResponse.builder()
            .totalRequested(0)
            .successfulRegistrations(0)
            .failedRegistrations(0)
            .errors(List.of(errorMessage))
            .build();
    }
}
