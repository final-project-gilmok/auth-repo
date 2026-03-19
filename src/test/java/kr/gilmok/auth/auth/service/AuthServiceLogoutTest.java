package kr.gilmok.auth.auth.service;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import kr.gilmok.auth.auth.entity.AuthSession;
import kr.gilmok.auth.auth.entity.User;
import kr.gilmok.auth.auth.repository.AuthSessionRepository;
import kr.gilmok.auth.global.jwt.JwtProvider;
import kr.gilmok.auth.global.jwt.TokenProvider;
import kr.gilmok.auth.global.util.TokenHashEncoder;
import kr.gilmok.common.security.AccessTokenBlocklistRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.lang.reflect.Constructor;
import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceLogoutTest {

    @InjectMocks
    private AuthService authService;

    @Mock
    private AuthSessionRepository authSessionRepository;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private TokenProvider tokenProvider;

    @Mock
    private JwtProvider jwtProvider;

    @Mock
    private TokenHashEncoder tokenHashEncoder;

    @Mock
    private AuthSessionService authSessionService;

    @Mock
    private MeterRegistry meterRegistry;

    @Mock
    private Counter counter;

    @Mock
    private AccessTokenBlocklistRepository accessTokenBlocklistRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Test
    @DisplayName("로그아웃 성공: refresh 세션 revoke + access token blocklist 등록")
    void logout_success() throws Exception {
        // given
        String accessToken = "valid.access.token";
        String refreshToken = "valid-refresh-token";
        String hashedRefresh = "hashed-refresh";
        String jti = "test-jti-uuid";
        long remainingTtlMs = 1_800_000L; // 30분

        User testUser = User.createNewUser("testuser", "password");
        AuthSession session = createSession(testUser, hashedRefresh, "127.0.0.1", "Agent",
                LocalDateTime.now().plusDays(7));

        given(tokenHashEncoder.encode(refreshToken)).willReturn(hashedRefresh);
        given(authSessionRepository.findByRefreshTokenHashAndActive(hashedRefresh))
                .willReturn(Optional.of(session));
        given(jwtProvider.getJti(accessToken)).willReturn(jti);
        given(jwtProvider.getRemainingTtlMs(accessToken)).willReturn(remainingTtlMs);

        // when
        assertThatCode(() -> authService.logout(accessToken, refreshToken))
                .doesNotThrowAnyException();

        // then
        verify(accessTokenBlocklistRepository).block(jti, remainingTtlMs);
        // session.getRevokedAt()이 ACTIVE_TIME과 달라졌는지 검증
        assert session.getRevokedAt().isAfter(AuthSessionRepository.ACTIVE_TIME);
    }

    @Test
    @DisplayName("로그아웃 - refresh 세션이 없어도 예외 없이 처리된다 (graceful)")
    void logout_noSession_graceful() {
        // given
        String accessToken = "valid.access.token";
        String refreshToken = "unknown-refresh-token";
        String hashedRefresh = "hashed-unknown";
        String jti = "test-jti-uuid";
        long remainingTtlMs = 900_000L;

        given(tokenHashEncoder.encode(refreshToken)).willReturn(hashedRefresh);
        given(authSessionRepository.findByRefreshTokenHashAndActive(hashedRefresh))
                .willReturn(Optional.empty());
        given(jwtProvider.getJti(accessToken)).willReturn(jti);
        given(jwtProvider.getRemainingTtlMs(accessToken)).willReturn(remainingTtlMs);

        // when & then: 예외 없이 완료
        assertThatCode(() -> authService.logout(accessToken, refreshToken))
                .doesNotThrowAnyException();

        verify(accessTokenBlocklistRepository).block(jti, remainingTtlMs);
    }

    @Test
    @DisplayName("로그아웃 - access token이 이미 만료된 경우 blocklist 등록 생략")
    void logout_expiredAccessToken_noBlocklist() {
        // given
        String accessToken = "already.expired.token";
        String refreshToken = null;

        given(jwtProvider.getJti(accessToken)).willThrow(new RuntimeException("Token expired"));

        // when & then
        assertThatCode(() -> authService.logout(accessToken, refreshToken))
                .doesNotThrowAnyException();

        verify(accessTokenBlocklistRepository, never()).block(anyString(), anyLong());
    }

    @Test
    @DisplayName("로그아웃 - access/refresh token 둘 다 null이어도 예외 없이 처리된다")
    void logout_nullTokens_graceful() {
        // when & then
        assertThatCode(() -> authService.logout(null, null))
                .doesNotThrowAnyException();

        verifyNoInteractions(accessTokenBlocklistRepository);
        verifyNoInteractions(authSessionRepository);
    }

    private AuthSession createSession(User user, String refreshTokenHash, String ip, String userAgent,
                                      LocalDateTime expiresAt) {
        try {
            Constructor<AuthSession> constructor = AuthSession.class.getDeclaredConstructor();
            constructor.setAccessible(true);
            AuthSession session = constructor.newInstance();
            ReflectionTestUtils.setField(session, "user", user);
            ReflectionTestUtils.setField(session, "refreshTokenHash", refreshTokenHash);
            ReflectionTestUtils.setField(session, "createdIp", ip);
            ReflectionTestUtils.setField(session, "userAgent", userAgent);
            ReflectionTestUtils.setField(session, "expiresAt", expiresAt);
            return session;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
