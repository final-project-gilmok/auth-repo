package kr.gilmok.auth.auth.repository;

import jakarta.persistence.LockModeType;
import kr.gilmok.auth.auth.entity.AuthSession;
import kr.gilmok.auth.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;

import java.util.List;
import java.util.Optional;

public interface AuthSessionRepository extends JpaRepository<AuthSession, Long> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<AuthSession> findByRefreshTokenHashAndRevokedAtIsNull(String hash);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<AuthSession> findByUserAndCreatedIpAndUserAgentAndRevokedAtIsNull(User user, String ip, String userAgent);

    List<AuthSession> findAllByUserAndRevokedAtIsNullOrderByIssuedAtAsc(User user);
}
