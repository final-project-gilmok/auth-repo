package kr.gilmok.auth.auth.service;

import kr.gilmok.auth.auth.entity.AuthSession;
import kr.gilmok.auth.auth.entity.User;
import kr.gilmok.auth.auth.exception.AuthErrorCode;
import kr.gilmok.auth.auth.repository.AuthSessionRepository;
import kr.gilmok.auth.global.util.HashUtil;
import kr.gilmok.common.exception.CustomException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Slf4j
public class AuthSessionService {

    private final AuthSessionRepository authSessionRepository;

    @Value(("${app.jwt.refresh-expiration-ms}"))
    private long refreshExpTime;

    @Transactional
    public void saveSession(User user, String refreshToken, String ip, String userAgent) {
        String hashedRefreshToken = HashUtil.hash(refreshToken);

        try {
            // 1. 동일 기기 세션 확인 및 업데이트 시도
            Optional<AuthSession> existingSameDeviceSession = authSessionRepository
                    .findByUserAndCreatedIpAndUserAgentAndRevokedAtIsNull(user, ip, userAgent);

            if (existingSameDeviceSession.isPresent()) {
                existingSameDeviceSession.get().updateRefreshToken(hashedRefreshToken, refreshExpTime);
                return;
            }

            // 2. 최대 개수 제한 로직
            List<AuthSession> activeSessions = authSessionRepository
                    .findAllByUserAndRevokedAtIsNullOrderByIssuedAtAsc(user);

            if (activeSessions.size() >= 3) {
                activeSessions.get(0).revoke();
            }

            // 3. 신규 저장 시도
            AuthSession newSession = AuthSession.createSession(user, hashedRefreshToken, ip, userAgent, refreshExpTime);
            authSessionRepository.save(newSession);

        } catch (DataIntegrityViolationException e) {
            // 4. 동시 INSERT 경합 발생 시: 다시 조회하여 업데이트로 전환
            log.warn("동시 로그인 경합 발생 - 기존 세션 업데이트로 전환: {}", user.getUsername());
            AuthSession retrySession = authSessionRepository
                    .findByUserAndCreatedIpAndUserAgentAndRevokedAtIsNull(user, ip, userAgent)
                    .orElseThrow(() -> new CustomException(AuthErrorCode.INVALID_SESSION));

            retrySession.updateRefreshToken(hashedRefreshToken, refreshExpTime);
        }
    }
}