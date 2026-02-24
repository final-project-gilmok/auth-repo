package kr.gilmok.auth.auth.service;

import kr.gilmok.auth.auth.entity.AuthSession;
import kr.gilmok.auth.auth.entity.User;
import kr.gilmok.auth.auth.repository.AuthSessionRepository;
import kr.gilmok.auth.global.util.HashUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthSessionService {

    private final AuthSessionRepository authSessionRepository;

    @Value(("${app.jwt.refresh-expiration-ms}"))
    private long refreshExpTime;

    @Transactional
    public void saveSession(User user, String refreshToken, String ip, String userAgent) {
        String hashedRefreshToken = HashUtil.hash(refreshToken);

        AuthSession session = AuthSession.createSession(user, hashedRefreshToken, ip, userAgent, refreshExpTime);
        session.updateLastUsedAt();

        authSessionRepository.save(session);
    }

}
