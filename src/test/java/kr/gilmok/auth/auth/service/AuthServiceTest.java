package kr.gilmok.auth.auth.service;

import kr.gilmok.auth.auth.dto.SignupRequest;
import kr.gilmok.auth.auth.entity.User;
import kr.gilmok.auth.auth.entity.UserStatus;
import kr.gilmok.auth.auth.exception.AuthErrorCode;
import kr.gilmok.auth.auth.repository.UserRepository;
import kr.gilmok.common.exception.CustomException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@ActiveProfiles("test")
public class AuthServiceTest {

    @InjectMocks
    private AuthService authService;

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Test
    @DisplayName("회원가입 성공 테스트")
    void signup_success() {
        // given
        SignupRequest request = new SignupRequest("testuser", "password123!", "password123!");
        given(userRepository.findByUsername(request.username())).willReturn(Optional.empty());
        given(passwordEncoder.encode(request.password())).willReturn("encodedPassword");

        // when
        authService.signup(request);

        // then
        verify(userRepository, times(1)).save(any(User.class));
        verify(passwordEncoder, times(1)).encode(anyString());
    }

    @Test
    @DisplayName("회원가입 실패 - 아이디 중복 테스트")
    void signup_fail_duplicate_username() {
        // given
        SignupRequest request = new SignupRequest("testuser", "password123!", "password123!");
        User existingUser = User.createNewUser("testuser", "oldPassword");

        given(userRepository.findByUsername(request.username())).willReturn(Optional.of(existingUser));

        // when & then
        CustomException exception = assertThrows(CustomException.class, () -> {
            authService.signup(request);
        });

        // ErrorCode 규격 확인 (U001: DUPLICATE_USERNAME)
        assertEquals(AuthErrorCode.DUPLICATE_USERNAME.getCode(), exception.getErrorCode().getCode());
        assertEquals(AuthErrorCode.DUPLICATE_USERNAME.getMessage(), exception.getMessage());
    }

    @Test
    @DisplayName("회원가입 실패 - 비밀번호 불일치")
    void signup_fail_password_mismatch() {
        // given: 서로 다른 비밀번호 입력
        SignupRequest request = new SignupRequest("testuser", "password123!", "wrongPassword");

        // when & then
        CustomException exception = assertThrows(CustomException.class, () -> {
            authService.signup(request);
        });

        assertEquals("U002", exception.getErrorCode().getCode());
        assertEquals("비밀번호가 일치하지 않습니다.", exception.getMessage());
    }

    @Test
    @DisplayName("관리자 계정 생성 시 ROLE_ADMIN 권한이 부여되어야 한다")
    void createAdmin_shouldHaveAdminRole() {
        // given
        String username = "adminUser";
        String password = "encodedPassword";

        // when: 정적 팩토리 메서드를 통해 관리자 생성
        User admin = User.createAdmin(username, password);

        // then
        assertNotNull(admin);
        assertEquals(username, admin.getUsername());

        // "ROLE_USER"가 아닌 "ROLE_ADMIN"이어야 함
        assertEquals("ROLE_ADMIN", admin.getRole());
        assertEquals(UserStatus.ACTIVE, admin.getStatus());
    }

    @Test
    @DisplayName("일반 유저 생성 시 ROLE_USER 권한이 부여되어야 한다")
    void createNewUser_shouldHaveUserRole() {
        // when
        User user = User.createNewUser("regularUser", "password");

        // then
        assertEquals("ROLE_USER", user.getRole());
    }
}
