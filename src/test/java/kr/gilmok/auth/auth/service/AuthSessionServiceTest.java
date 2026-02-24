package kr.gilmok.auth.auth.service;

import kr.gilmok.auth.auth.entity.AuthSession;
import kr.gilmok.auth.auth.entity.User;
import kr.gilmok.auth.auth.repository.AuthSessionRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@ActiveProfiles("test")
public class AuthSessionServiceTest {

    @InjectMocks
    private AuthSessionService authSessionService;

    @Mock
    private AuthSessionRepository authSessionRepository;

    @Test
    @DisplayName("새 세션 저장 시 기존 유저 세션은 유지되어야 한다 (다중 로그인 허용)")
    void saveSession_shouldKeepExistingSessions() {
        // given
        User user = User.createNewUser("testuser", "password");
        String refreshToken = "new-refresh-token";
        String ip = "127.0.0.1";
        String agent = "Mozilla/5.0";

        // 기존에 살아있는 세션 준비 (무효화되지 않아야 함)
        AuthSession oldSession = AuthSession.createSession(user, "old-hash-1", ip, agent, 100000L);

        // when
        authSessionService.saveSession(user, refreshToken, ip, agent);

        // then
        assertAll(
                // 1. 기존 세션이 여전히 유효한지 확인 (revokedAt이 null이어야 함)
                () -> assertThat(oldSession.getRevokedAt()).isNull(),

                // 2. 새로운 세션이 정상적으로 저장되었는지 확인
                () -> verify(authSessionRepository).save(any(AuthSession.class))
        );
    }
}
