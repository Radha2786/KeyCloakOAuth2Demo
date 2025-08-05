package com.example.demoOAuth.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.time.LocalDateTime;

@Entity
@Table(name = "user_roles")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserRole {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "role_id", nullable = false)
    private Role role;
    
    @Column(name = "assigned_at")
    private LocalDateTime assignedAt;
    
    @Column(name = "assigned_by")
    private String assignedBy; // Username who assigned this role
    
    @Enumerated(EnumType.STRING)
    @Column(name = "assignment_method")
    private AssignmentMethod assignmentMethod;
    
    @Column(name = "is_active")
    @Builder.Default
    private Boolean isActive = true;
    
    @PrePersist
    protected void onCreate() {
        assignedAt = LocalDateTime.now();
    }
    
    public enum AssignmentMethod {
        SELF_REGISTRATION,
        ADMIN_ASSIGNED,
        SYSTEM_DEFAULT
    }
}
