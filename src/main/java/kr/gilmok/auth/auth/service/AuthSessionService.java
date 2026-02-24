package kr.gilmok.auth.auth.service;

import kr.gilmok.auth.auth.entity.AuthSession;
import kr.gilmok.auth.auth.entity.User;
import kr.gilmok.auth.auth.repository.AuthSessionRepository;
import kr.gilmok.auth.global.util.HashUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

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

        // 1. 동일 기기(IP + UA)에서 온 활성 세션이 있는지 확인
        Optional<AuthSession> existingSameDeviceSession = authSessionRepository
                .findByUserAndCreatedIpAndUserAgentAndRevokedAtIsNull(user, ip, userAgent);

        if (existingSameDeviceSession.isPresent()) {
            // 동일 기기라면 기존 레코드를 갱신
            AuthSession session = existingSameDeviceSession.get();
            session.updateRefreshToken(hashedRefreshToken, refreshExpTime);
            return; // 갱신 후 종료
        }

        // 2. 새로운 기기인 경우, 현재 활성 세션 개수 체크 (오래된 순 정렬)
        List<AuthSession> activeSessions = authSessionRepository
                .findAllByUserAndRevokedAtIsNullOrderByIssuedAtAsc(user);

        // 계정당 최대 개수 제한 3개
        if (activeSessions.size() >= 3) {
            AuthSession oldest = activeSessions.get(0);
            oldest.revoke(); // 가장 오래된 세션 만료
        }

        // 3. 신규 세션 저장
        AuthSession newSession = AuthSession.createSession(user, hashedRefreshToken, ip, userAgent, refreshExpTime);
        authSessionRepository.save(newSession);
    }
}