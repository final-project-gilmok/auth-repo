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

import java.util.List;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@ActiveProfiles("test")
public class AuthSessionServiceTest {

    @InjectMocks
    private AuthSessionService authSessionService;

    @Mock
    private AuthSessionRepository authSessionRepository;

    @Test
    @DisplayName("새 세션 저장 시 기존 유저 세션은 모두 무효화되어야 한다")
    void saveSession_shouldRevokeExistingSessions() {
        // given
        User user = User.createNewUser("testuser", "password");
        String refreshToken = "new-refresh-token";
        String ip = "127.0.0.1";
        String agent = "Mozilla/5.0";

        // 기존에 살아있던 세션들 모킹
        AuthSession oldSession1 = AuthSession.createSession(user, "old-hash-1", ip, agent, 100000L);
        AuthSession oldSession2 = AuthSession.createSession(user, "old-hash-2", ip, agent, 100000L);
        List<AuthSession> existingSessions = List.of(oldSession1, oldSession2);

        given(authSessionRepository.findAllByUserAndRevokedAtIsNull(user))
                .willReturn(existingSessions);

        // when
        authSessionService.saveSession(user, refreshToken, ip, agent);

        // then
        assertAll(
                // 1. 기존 세션들이 모두 revoke 되었는지 확인 (revokedAt 필드가 채워졌는지)
                () -> assertThat(oldSession1.getRevokedAt()).isNotNull(),
                () -> assertThat(oldSession2.getRevokedAt()).isNotNull(),

                // 2. 새로운 세션이 저장(save) 호출되었는지 확인
                () -> verify(authSessionRepository).save(any(AuthSession.class))
        );
    }
}
