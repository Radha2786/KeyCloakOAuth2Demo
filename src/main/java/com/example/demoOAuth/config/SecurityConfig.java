package com.example.demoOAuth.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.nimbusds.jwt.JWT;

import jakarta.persistence.Converts;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@Slf4j
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(authz -> authz
                // Public endpoints - no authentication required
                .requestMatchers("/api/register", "/api/login", "/api/refresh-token", "/api/health").permitAll()
                
                // Protected endpoints - require authentication
                .requestMatchers("/api/profile", "/api/test/authenticated", "/api/test/protected").authenticated()
                
                // Admin endpoints - require admin role
                .requestMatchers("/api/admin/**").hasRole("admin")
                
                
                // All other requests require authentication
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
            );
        
        return http.build();
    }
    
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        
        // Convert realm roles and resource roles to Spring Security authorities
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            
            // Extract realm roles
            Collection<GrantedAuthority> authorities = extractRealmRoles(jwt);
            
            // Extract resource roles (client-specific roles)
            authorities.addAll(extractResourceRoles(jwt));
            
            // Extract scopes
            authorities.addAll(extractScopes(jwt));
            
            log.debug("Extracted authorities for user {}: {}", 
                     jwt.getClaimAsString("preferred_username"), authorities);
            
            return authorities;
        });
        
        // Set principal name to preferred_username
        converter.setPrincipalClaimName("preferred_username");
        // principalClaimName tells Spring Security which claim (field) in the JWT token should be treated 
        // as the username (or main identity) of the logged-in user.
        
        return converter;
    }
    
    // Gets roles from realm_access.roles in the JWT
    @SuppressWarnings("unchecked")
    private Collection<GrantedAuthority> extractRealmRoles(org.springframework.security.oauth2.jwt.Jwt jwt) {
        Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
        if (realmAccess != null && realmAccess.containsKey("roles")) {
            List<String> roles = (List<String>) realmAccess.get("roles");
            return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());
        }
        return List.of();
    }
    // how this is working 
    // Gets roles from realm_access.roles in the JWT
    // Converts them to ROLE_<role> format for Spring
//     example : "realm_access": {
//   "roles": ["user", "admin"]
// }
// → Becomes: ROLE_user, ROLE_admin



// "resource_access": {
//   "myclient": {
//     "roles": ["editor", "manager"]
//   }
// }
    @SuppressWarnings("unchecked")
    private Collection<GrantedAuthority> extractResourceRoles(org.springframework.security.oauth2.jwt.Jwt jwt) {
        Map<String, Object> resourceAccess = jwt.getClaimAsMap("resource_access");
        if (resourceAccess != null) {
            return resourceAccess.entrySet().stream()
                .filter(entry -> entry.getValue() instanceof Map)
                .flatMap(entry -> {
                    Map<String, Object> resource = (Map<String, Object>) entry.getValue();
                    if (resource.containsKey("roles")) {
                        List<String> roles = (List<String>) resource.get("roles");
                        return roles.stream()
                            .map(role -> new SimpleGrantedAuthority("ROLE_" + role));
                    }
                    return java.util.stream.Stream.empty();
                })
                .collect(Collectors.toList());
        }
        return List.of();
    }
    
    // Gets the space-separated scope claim and converts each into SCOPE_<scope>.
    // Example:
    // "scope": "read write"
    // Becomes: SCOPE_read, SCOPE_write
    private Collection<GrantedAuthority> extractScopes(org.springframework.security.oauth2.jwt.Jwt jwt) {
        String scopes = jwt.getClaimAsString("scope");
        if (scopes != null && !scopes.trim().isEmpty()) {
            return List.of(scopes.split(" ")).stream()
                .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
                .collect(Collectors.toList());
        }
        return List.of();
    }
    
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // Allow specific origins (configure according to your frontend URL)
        configuration.setAllowedOriginPatterns(List.of(
            "http://localhost:3000",  // React default
            "http://localhost:4200",  // Angular default
            "http://localhost:8000",  // Vue default
            "http://localhost:9876"   // Same origin (for testing)
        ));
        
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        
        return source;
    }
}
