package kr.gilmok.auth.auth.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "auth_sessions", uniqueConstraints = {
        @UniqueConstraint(name = "uk_auth_session_device", columnNames = {"user_id", "created_ip", "user_agent",
                "revoked_at"})
})
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class AuthSession {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 255)
    private String refreshTokenHash;

    @Column(length = 45) // IPv6 대응
    private String createdIp;

    @Column(length = 512) // 긴 User-Agent 대응
    private String userAgent;

    @Column(nullable = false)
    private LocalDateTime issuedAt;

    @Column(nullable = false)
    private LocalDateTime lastUsedAt;

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    @Column(nullable = false)
    private LocalDateTime revokedAt = LocalDateTime.of(1970, 1, 1, 0, 0);

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    // RTR: 기존 세션 무효화
    public void revoke() {
        this.revokedAt = LocalDateTime.now();
    }
}