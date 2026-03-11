package kr.gilmok.auth.auth.service;

import kr.gilmok.auth.auth.entity.AuthSession;
import kr.gilmok.auth.auth.entity.User;
import kr.gilmok.auth.auth.repository.AuthSessionRepository;
import kr.gilmok.auth.global.util.TokenHashEncoder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthSessionService {

    private final AuthSessionRepository authSessionRepository;
    private final TokenHashEncoder tokenHashEncoder;

    @Value("${app.jwt.refresh-expiration-ms}")
    private long refreshExpTime;

    @Transactional
    public void saveSession(User user, String refreshToken, String ip, String userAgent) {
        String hashedRefreshToken = tokenHashEncoder.encode(refreshToken);
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime expiresAt = now.plusNanos(refreshExpTime * 1_000_000L);

        // 1. 현재 활성 세션 개수 체크 (오래된 순 정렬)
        List<AuthSession> activeSessions = authSessionRepository.findAllActiveSessionsByUser(user);

        // 최적화: 방금 로그인한 기기가 이미 목록에 있다면 Upsert(수정)될 것이므로 개수가 늘어나지 않음.
        // 다른 기기에서 로그인해서 총 개수가 3개를 초과하게 될 때만 가장 오래된 세션 만료
        // DDD: Entity 내부 책임을 활용하여 Tell, Don't ask 원칙 준수
        boolean isSameDeviceExists = activeSessions.stream()
                .anyMatch(s -> s.isSameDevice(ip, userAgent));

        if (!isSameDeviceExists && activeSessions.size() >= 3) {
            AuthSession oldest = activeSessions.get(0);
            oldest.revoke(); // JPA 변경 감지(Dirty Checking)로 UPDATE 쿼리 발생
        }

        // 2. Native Query 한 방으로 삽입 또는 갱신 (DB 엔진이 동시성 완벽 제어)
        authSessionRepository.upsertAuthSession(user.getId(), hashedRefreshToken, ip, userAgent, now, expiresAt,
                AuthSessionRepository.ACTIVE_TIME);
    }
}