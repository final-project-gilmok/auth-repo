package kr.gilmok.auth.auth.service;

import kr.gilmok.auth.auth.dto.LoginRequest;
import kr.gilmok.auth.auth.dto.LoginResponse;
import kr.gilmok.auth.auth.entity.User;
import kr.gilmok.auth.auth.repository.UserRepository;
import kr.gilmok.auth.global.Jwt.JwtProvider;
import kr.gilmok.common.dto.AuthUserDto;
import kr.gilmok.common.security.CustomUserDetails;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@ActiveProfiles("test")
public class AuthServiceLoginTest {

    @InjectMocks
    private AuthService authService;

    @Mock
    private UserRepository userRepository;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private JwtProvider jwtProvider;

    @Mock
    private AuthSessionService authSessionService;

    @Test
    @DisplayName("로그인 성공 시 토큰을 발급하고 세션을 저장한다")
    void login_success() {
        // given
        String username = "testuser";
        String password = "password";
        String ip = "127.0.0.1";
        String userAgent = "Mozilla/5.0";
        LoginRequest request = new LoginRequest(username, password);

        User user = User.createNewUser(username, "encodedPassword");
        AuthUserDto dto = new AuthUserDto(user.getId(), user.getUsername(), user.getPasswordHash(), user.getRole(), user.getStatus().name());
        CustomUserDetails userDetails = new CustomUserDetails(dto);

        // (1) Security 인증 모킹
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null);
        given(authenticationManager.authenticate(any())).willReturn(authentication);

        // 2. 실제 서비스 로직이 사용하는 getReferenceById를 모킹
        // getReferenceById는 Optional이 아니라 객체 자체를 반환하므로 Optional.of()를 해야 함
        given(userRepository.getReferenceById(user.getId())).willReturn(user);

        given(jwtProvider.createAccessToken(user)).willReturn("access-token");
        given(jwtProvider.createRefreshToken(user)).willReturn("refresh-token");

        // when
        LoginResponse response = authService.login(request, ip, userAgent);

        // then
        assertAll(
                () -> assertThat(response.accessToken()).isEqualTo("access-token"),
                () -> assertThat(response.refreshToken()).isEqualTo("refresh-token"),
                () -> assertThat(response.username()).isEqualTo(username),

                // 3. 검증 로직도 getReferenceById가 호출되었는지 확인하는 것으로 변경
                () -> verify(userRepository).getReferenceById(user.getId()),
                () -> verify(authSessionService).saveSession(eq(user), eq("refresh-token"), eq(ip), eq(userAgent))
        );
    }

    @Test
    @DisplayName("인증에 실패하면 예외가 발생한다")
    void login_fail_invalid_credentials() {
        // given
        LoginRequest request = new LoginRequest("wrongUser", "wrongPassword");
        given(authenticationManager.authenticate(any()))
                .willThrow(new BadCredentialsException("인증 실패"));

        // when & then
        assertThatThrownBy(() -> authService.login(request, "ip", "agent"))
                .isInstanceOf(BadCredentialsException.class);
    }
}
