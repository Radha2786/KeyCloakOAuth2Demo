package com.example.demoOAuth.repository;

import com.example.demoOAuth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    Optional<User> findByUsername(String username);
    
    Optional<User> findByEmail(String email);
    
    Optional<User> findByKeycloakUserId(String keycloakUserId);
    
    boolean existsByUsername(String username);
    
    boolean existsByEmail(String email);
}
