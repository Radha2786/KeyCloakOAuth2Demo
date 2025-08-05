package com.example.demoOAuth.repository;

import com.example.demoOAuth.entity.UserRole;
import com.example.demoOAuth.entity.User;
import com.example.demoOAuth.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRoleRepository extends JpaRepository<UserRole, Long> {
    
    List<UserRole> findByUserAndIsActiveTrue(User user);
    
    List<UserRole> findByRoleAndIsActiveTrue(Role role);
    
    Optional<UserRole> findByUserAndRoleAndIsActiveTrue(User user, Role role);
    
    @Query("SELECT ur.role.name FROM UserRole ur WHERE ur.user = :user AND ur.isActive = true")
    List<String> findActiveRoleNamesByUser(@Param("user") User user);
    
    boolean existsByUserAndRoleAndIsActiveTrue(User user, Role role);
}
