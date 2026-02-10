package kr.gilmok.auth.auth.service;

import kr.gilmok.auth.auth.dto.SignupRequest;
import kr.gilmok.auth.auth.entity.User;
import kr.gilmok.auth.auth.exception.UserErrorCode;
import kr.gilmok.auth.auth.repository.UserRepository;
import kr.gilmok.common.exception.CustomException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
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
        SignupRequest request = new SignupRequest("testuser", "password123!");
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
        SignupRequest request = new SignupRequest("testuser", "password123!");
        User existingUser = User.createNewUser("testuser", "oldPassword");

        given(userRepository.findByUsername(request.username())).willReturn(Optional.of(existingUser));

        // when & then
        CustomException exception = assertThrows(CustomException.class, () -> {
            authService.signup(request);
        });

        // ErrorCode 규격 확인 (U001: DUPLICATE_USERNAME)
        assertEquals(UserErrorCode.DUPLICATE_USERNAME.getCode(), exception.getErrorCode().getCode());
        assertEquals(UserErrorCode.DUPLICATE_USERNAME.getMessage(), exception.getMessage());
    }
}
