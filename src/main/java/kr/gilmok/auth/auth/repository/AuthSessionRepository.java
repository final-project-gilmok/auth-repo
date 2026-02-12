package kr.gilmok.auth.auth.repository;

import kr.gilmok.auth.auth.entity.AuthSession;
import kr.gilmok.auth.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface AuthSessionRepository extends JpaRepository<AuthSession, Long> {
    Optional<AuthSession> findByRefreshTokenHashAndRevokedAtIsNull(String hash);

    List<AuthSession> findAllByUserAndRevokedAtIsNull(User user);
}
