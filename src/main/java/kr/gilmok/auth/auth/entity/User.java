package kr.gilmok.auth.auth.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@Table(name = "users")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@EntityListeners(AuditingEntityListener.class)
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 50, unique = true)
    private String username;

    @Column(name = "password_hash", nullable = false, length = 100)
    private String passwordHash;

    @Column(length = 20)
    private String role;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private UserStatus status;

    private LocalDateTime lastLoginAt;

    @CreatedDate
    @Column(updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    private LocalDateTime updatedAt;

    @Builder
    private User(String username, String passwordHash, String role, UserStatus status) {
        this.username = username;
        this.passwordHash = passwordHash;
        this.role = (role != null) ? role : "ROLE_USER";
        this.status = (status != null) ? status : UserStatus.ACTIVE;
    }

    public static User createNewUser(String username, String encodedPassword) {
        return User.builder()
                .username(username)
                .passwordHash(encodedPassword)
                .role("ROLE_USER")
                .status(UserStatus.ACTIVE)
                .build();
    }

    public static User createAdmin(String username, String encodedPassword) {
        return User.builder()
                .username(username)
                .passwordHash(encodedPassword)
                .role("ROLE_ADMIN")
                .status(UserStatus.ACTIVE)
                .build();
    }
}