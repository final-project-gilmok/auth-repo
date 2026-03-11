package kr.gilmok.auth.auth.service;

import kr.gilmok.auth.auth.dto.AuthTokenDto;
import kr.gilmok.auth.auth.entity.AuthSession;
import kr.gilmok.auth.auth.entity.User;
import kr.gilmok.auth.auth.exception.AuthErrorCode;
import kr.gilmok.auth.auth.repository.AuthSessionRepository;
import kr.gilmok.auth.global.Jwt.JwtProvider;
import kr.gilmok.auth.global.util.HashUtil;
import kr.gilmok.common.exception.CustomException;
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
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
public class AuthServiceReissueTest {

    @InjectMocks
    private AuthService authService;

    @Mock
    private AuthSessionRepository authSessionRepository;

    @Mock
    private JwtProvider jwtProvider;

    @Mock
    private AuthSessionService authSessionService;

    private User testUser;
    private AuthSession validSession;

    @BeforeEach
    void setUp() {
        // accessExpTime 세팅
        ReflectionTestUtils.setField(authService, "accessExpTime", 3600000L);

        testUser = User.createNewUser("testuser", "password");
        validSession = createSession(testUser, HashUtil.hash("old-refresh-token"), "127.0.0.1", "TestAgent",
                LocalDateTime.now().plusDays(14));
    }

    private AuthSession createSession(User user, String refreshTokenHash, String createdIp, String userAgent,
                                      LocalDateTime expiresAt) {
        try {
            Constructor<AuthSession> constructor = AuthSession.class.getDeclaredConstructor();
            constructor.setAccessible(true);
            AuthSession session = constructor.newInstance();
            ReflectionTestUtils.setField(session, "user", user);
            ReflectionTestUtils.setField(session, "refreshTokenHash", refreshTokenHash);
            ReflectionTestUtils.setField(session, "createdIp", createdIp);
            ReflectionTestUtils.setField(session, "userAgent", userAgent);
            ReflectionTestUtils.setField(session, "expiresAt", expiresAt);
            return session;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("토큰 재발급 성공 시 이전 세션을 무효화하고 새 토큰을 반환한다")
    void reissue_success() {
        // given
        String oldRefreshToken = "old-refresh-token";
        String hashedToken = HashUtil.hash(oldRefreshToken);
        String newAccessToken = "new-access-token";
        String newRefreshToken = "new-refresh-token";
        String ip = "192.168.0.2";
        String userAgent = "NewAgent";

        given(authSessionRepository.findByRefreshTokenHashAndActive(hashedToken))
                .willReturn(Optional.of(validSession));
        given(jwtProvider.createAccessToken(testUser)).willReturn(newAccessToken);
        given(jwtProvider.createRefreshToken(testUser)).willReturn(newRefreshToken);

        // when
        assertThat(validSession.getRevokedAt()).isEqualTo(AuthSessionRepository.ACTIVE_TIME);

        AuthTokenDto response = authService.reissue(oldRefreshToken, ip, userAgent);

        // then
        assertThat(response.accessToken()).isEqualTo(newAccessToken);
        assertThat(response.refreshToken()).isEqualTo(newRefreshToken);
        assertThat(response.username()).isEqualTo(testUser.getUsername());
        assertThat(validSession.getRevokedAt()).isAfter(AuthSessionRepository.ACTIVE_TIME); // 기존 세션이 무효화 되었는지 확인

        verify(authSessionRepository).flush();
        verify(authSessionService).saveSession(eq(testUser), eq(newRefreshToken), eq(ip), eq(userAgent));
    }

    @Test
    @DisplayName("유효하지 않은 리프레시 토큰으로 재발급 요청 시 예외가 발생한다")
    void reissue_fail_invalidToken() {
        // given
        String invalidToken = "invalid-token";
        given(authSessionRepository.findByRefreshTokenHashAndActive(any()))
                .willReturn(Optional.empty());

        // when & then
        assertThatThrownBy(() -> authService.reissue(invalidToken, "ip", "agent"))
                .isInstanceOf(CustomException.class)
                .extracting("errorCode")
                .isEqualTo(AuthErrorCode.INVALID_REFRESH_TOKEN);
    }

    @Test
    @DisplayName("만료된 리프레시 토큰으로 재발급 요청 시 예외가 발생한다")
    void reissue_fail_expiredToken() {
        // given
        String expiredToken = "expired-token";
        String hashedToken = HashUtil.hash(expiredToken);
        AuthSession expiredSession = createSession(testUser, hashedToken, "127.0.0.1", "TestAgent",
                LocalDateTime.now().minusDays(1));

        given(authSessionRepository.findByRefreshTokenHashAndActive(hashedToken))
                .willReturn(Optional.of(expiredSession));

        // when & then
        assertThatThrownBy(() -> authService.reissue(expiredToken, "ip", "agent"))
                .isInstanceOf(CustomException.class)
                .extracting("errorCode")
                .isEqualTo(AuthErrorCode.REFRESH_TOKEN_EXPIRED);
    }
}
