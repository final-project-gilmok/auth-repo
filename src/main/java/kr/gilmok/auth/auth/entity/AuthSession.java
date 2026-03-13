package kr.gilmok.auth.auth.entity;

import jakarta.persistence.*;
import kr.gilmok.auth.auth.exception.AuthErrorCode;
import kr.gilmok.common.exception.CustomException;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Objects;

@Entity
@Table(name = "auth_sessions", indexes = {
        @Index(name = "idx_auth_session_hash", columnList = "refresh_token_hash")
}, uniqueConstraints = {
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

    // 만료 여부 검증
    public void validateExpiration(LocalDateTime now) {
        if (!this.expiresAt.isAfter(now)) {
            throw new CustomException(AuthErrorCode.REFRESH_TOKEN_EXPIRED);
        }
    }

    // 동일 기기 여부 검증
    public boolean isSameDevice(String ip, String userAgent) {
        return Objects.equals(this.createdIp, ip) &&
                Objects.equals(this.userAgent, userAgent);
    }
}