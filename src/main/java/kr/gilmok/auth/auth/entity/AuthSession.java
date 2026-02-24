package kr.gilmok.auth.auth.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "auth_sessions")
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

    private LocalDateTime revokedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Builder(access = AccessLevel.PRIVATE)
    private AuthSession(String refreshTokenHash, String createdIp, String userAgent, LocalDateTime expiresAt, User user) {
        this.refreshTokenHash = refreshTokenHash;
        this.createdIp = createdIp;
        this.userAgent = userAgent;
        this.issuedAt = LocalDateTime.now();
        this.lastUsedAt = LocalDateTime.now();
        this.expiresAt = expiresAt;
        this.user = user;
    }

    public static AuthSession createSession(User user, String tokenHash, String ip, String userAgent, long expMs) {
        return AuthSession.builder()
                .user(user)
                .refreshTokenHash(tokenHash)
                .createdIp(ip)
                .userAgent(userAgent)
                .expiresAt(LocalDateTime.now().plusNanos(expMs * 1_000_000L))
                .build();
    }

    // RTR: 기존 세션 무효화
    public void revoke() {
        this.revokedAt = LocalDateTime.now();
    }

    public void updateRefreshToken(String refreshTokenHash, Long refreshExpTime) {
        LocalDateTime now = LocalDateTime.now();

        this.refreshTokenHash = refreshTokenHash;
        this.issuedAt = now;
        this.lastUsedAt = now;
        this.expiresAt = now.plusSeconds(refreshExpTime);
    }
}