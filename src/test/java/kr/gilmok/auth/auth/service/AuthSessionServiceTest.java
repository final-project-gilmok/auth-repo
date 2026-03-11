package kr.gilmok.auth.auth.service;

import kr.gilmok.auth.auth.entity.AuthSession;
import kr.gilmok.auth.auth.entity.User;
import kr.gilmok.auth.auth.repository.AuthSessionRepository;
import kr.gilmok.auth.global.util.HashUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.lang.reflect.Constructor;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
public class AuthSessionServiceTest {

    @InjectMocks
    private AuthSessionService authSessionService;

    @Mock
    private AuthSessionRepository authSessionRepository;

    private User testUser;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(authSessionService, "refreshExpTime", 604800000L); // 7 days in ms
        testUser = User.createNewUser("testuser", "password");
        ReflectionTestUtils.setField(testUser, "id", 1L);
    }

    private AuthSession createSession(User user, String createdIp, String userAgent) {
        try {
            Constructor<AuthSession> constructor = AuthSession.class.getDeclaredConstructor();
            constructor.setAccessible(true);
            AuthSession session = constructor.newInstance();
            ReflectionTestUtils.setField(session, "user", user);
            ReflectionTestUtils.setField(session, "createdIp", createdIp);
            ReflectionTestUtils.setField(session, "userAgent", userAgent);
            return session;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("동일 기기에서 로그인 시 기존 세션은 무효화(삭제/업데이트)되지 않고 Upsert 쿼리가 실행된다")
    void saveSession_sameDevice_doesNotRevoke() {
        // given
        String refreshToken = "refresh-token";
        String ip = "192.168.0.1";
        String userAgent = "Mozilla/5.0";

        List<AuthSession> activeSessions = new ArrayList<>();
        AuthSession existingSession = createSession(testUser, ip, userAgent);
        activeSessions.add(existingSession);

        given(authSessionRepository.findAllActiveSessionsByUser(testUser)).willReturn(activeSessions);

        // when
        authSessionService.saveSession(testUser, refreshToken, ip, userAgent);

        // then
        // 기존 세션이 revoke 되지 않았음을 확인 (revokedAt이 1970-01-01 그대로인지)
        assertThat(existingSession.getRevokedAt()).isEqualTo(AuthSessionRepository.ACTIVE_TIME);

        // upsert 호출 여부 검증
        String hashedToken = HashUtil.hash(refreshToken);
        verify(authSessionRepository).upsertAuthSession(eq(testUser.getId()), eq(hashedToken), eq(ip), eq(userAgent),
                any(), any(), eq(AuthSessionRepository.ACTIVE_TIME));
    }

    @Test
    @DisplayName("다른 기기에서 로그인하여 활성 세션이 3개 이상이 될 경우 가장 오래된 세션이 무효화(revoke)된다")
    void saveSession_differentDevice_revokesOldestWhenLimitExceeded() {
        // given
        String refreshToken = "refresh-token-new";
        String ip = "192.168.0.4"; // 4번째 기기
        String userAgent = "Mozilla/5.0";

        List<AuthSession> activeSessions = new ArrayList<>();
        AuthSession oldestSession = createSession(testUser, "192.168.0.1", "Agent1");
        AuthSession middleSession = createSession(testUser, "192.168.0.2", "Agent2");
        AuthSession newestSession = createSession(testUser, "192.168.0.3", "Agent3");

        activeSessions.add(oldestSession);
        activeSessions.add(middleSession);
        activeSessions.add(newestSession);

        given(authSessionRepository.findAllActiveSessionsByUser(testUser)).willReturn(activeSessions);

        // when
        authSessionService.saveSession(testUser, refreshToken, ip, userAgent);

        // then
        // 가장 오래된 세션이 revoke 되었음을 확인
        assertThat(oldestSession.getRevokedAt()).isNotEqualTo(LocalDateTime.of(1970, 1, 1, 0, 0));
        // 나머지 세션은 변경되지 않았음을 확인
        assertThat(middleSession.getRevokedAt()).isEqualTo(LocalDateTime.of(1970, 1, 1, 0, 0));
        assertThat(newestSession.getRevokedAt()).isEqualTo(LocalDateTime.of(1970, 1, 1, 0, 0));

        // upsert 호출 여부 검증
        String hashedToken = HashUtil.hash(refreshToken);
        verify(authSessionRepository).upsertAuthSession(eq(testUser.getId()), eq(hashedToken), eq(ip), eq(userAgent),
                any(), any(), eq(AuthSessionRepository.ACTIVE_TIME));
    }

    @Test
    @DisplayName("다른 기기에서 로그인하더라도 활성 세션이 3개 미만이면 기존 세션은 무효화되지 않는다")
    void saveSession_differentDevice_underLimit_doesNotRevoke() {
        // given
        String refreshToken = "refresh-token-new";
        String ip = "192.168.0.3"; // 3번째 기기
        String userAgent = "Mozilla/5.0";

        List<AuthSession> activeSessions = new ArrayList<>();
        AuthSession session1 = createSession(testUser, "192.168.0.1", "Agent1");
        AuthSession session2 = createSession(testUser, "192.168.0.2", "Agent2");

        activeSessions.add(session1);
        activeSessions.add(session2);

        given(authSessionRepository.findAllActiveSessionsByUser(testUser)).willReturn(activeSessions);

        // when
        authSessionService.saveSession(testUser, refreshToken, ip, userAgent);

        // then
        // 기존 세션들이 revoke 되지 않았음을 확인
        assertThat(session1.getRevokedAt()).isEqualTo(LocalDateTime.of(1970, 1, 1, 0, 0));
        assertThat(session2.getRevokedAt()).isEqualTo(LocalDateTime.of(1970, 1, 1, 0, 0));

        // upsert 호출 여부 검증
        String hashedToken = HashUtil.hash(refreshToken);
        verify(authSessionRepository).upsertAuthSession(eq(testUser.getId()), eq(hashedToken), eq(ip), eq(userAgent),
                any(), any(), eq(AuthSessionRepository.ACTIVE_TIME));
    }
}
