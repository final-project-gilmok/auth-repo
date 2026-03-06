package kr.gilmok.auth.auth.repository;

import jakarta.persistence.LockModeType;
import kr.gilmok.auth.auth.entity.AuthSession;
import kr.gilmok.auth.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface AuthSessionRepository extends JpaRepository<AuthSession, Long> {

    LocalDateTime ACTIVE_TIME = LocalDateTime.of(1970, 1, 1, 0, 0);

    // JPA 기본 쿼리 메서드 (실제 DB와 통신, 파라미터로 LocalDateTime 받음)
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<AuthSession> findByRefreshTokenHashAndRevokedAt(String hash, LocalDateTime revokedAt);

    List<AuthSession> findAllByUserAndRevokedAtOrderByIssuedAtAsc(User user, LocalDateTime revokedAt);

    // Service에서 호출할 Default 메서드 (상수 자동 주입)
    default Optional<AuthSession> findByRefreshTokenHashAndActive(String hash) {
        return findByRefreshTokenHashAndRevokedAt(hash, ACTIVE_TIME);
    }

    default List<AuthSession> findAllActiveSessionsByUser(User user) {
        return findAllByUserAndRevokedAtOrderByIssuedAtAsc(user, ACTIVE_TIME);
    }

    // Native Query를 이용한 DB 레벨의 Upsert (동시성 완벽 제어)
    @Modifying
    @Query(value = """
            INSERT INTO auth_sessions (user_id, refresh_token_hash, created_ip, user_agent, issued_at, last_used_at, expires_at, revoked_at)
            VALUES (:userId, :tokenHash, :ip, :userAgent, :now, :now, :expiresAt, :revokedAt)
            ON DUPLICATE KEY UPDATE
                refresh_token_hash = VALUES(refresh_token_hash),
                issued_at = VALUES(issued_at),
                last_used_at = VALUES(last_used_at),
                expires_at = VALUES(expires_at)
            """, nativeQuery = true)
    void upsertAuthSession(
            @Param("userId") Long userId,
            @Param("tokenHash") String tokenHash,
            @Param("ip") String ip,
            @Param("userAgent") String userAgent,
            @Param("now") LocalDateTime now,
            @Param("expiresAt") LocalDateTime expiresAt,
            @Param("revokedAt") LocalDateTime revokedAt);
}