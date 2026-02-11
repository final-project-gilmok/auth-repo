package kr.gilmok.auth.auth.service;

import kr.gilmok.auth.auth.dto.LoginRequest;
import kr.gilmok.auth.auth.dto.LoginResponse;
import kr.gilmok.auth.auth.dto.SignupRequest;
import kr.gilmok.auth.auth.entity.User;
import kr.gilmok.auth.auth.exception.UserErrorCode;
import kr.gilmok.auth.auth.repository.UserRepository;
import kr.gilmok.auth.global.Jwt.JwtProvider;
import kr.gilmok.common.exception.CustomException;
import kr.gilmok.common.security.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;
    private final AuthenticationManager authenticationManager;

    @Transactional
    public void signup(SignupRequest request) {
        validatePasswordMatch(request.password(), request.passwordConfirm());
        validateDuplicateUsername(request.username());

        String encodedPassword = passwordEncoder.encode(request.password());
        User user = User.createNewUser(request.username(), encodedPassword);

        userRepository.save(user);
    }

    private void validatePasswordMatch(String password, String passwordConfirm) {
        if (!password.equals(passwordConfirm)) {
            throw new CustomException(UserErrorCode.PASSWORD_MISMATCH);
        }
    }

    private void validateDuplicateUsername(String username) {
        userRepository.findByUsername(username).ifPresent(user -> {
            throw new CustomException(UserErrorCode.DUPLICATE_USERNAME);
        });
    }

    @Transactional
    public LoginResponse login(LoginRequest request) {
        // 1. Spring Security 표준 인증 시도
        Authentication authentication = authenticationManager.authenticate( // -> CustomUserDetailsService 실행
                new UsernamePasswordAuthenticationToken(request.username(), request.password())
        );

        // 2. 인증 성공시 유저 정보 추출
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();

        // 3. 접속 시간 업데이트
        User user = userRepository.findByUsername(userDetails.getUsername())
                .orElseThrow(() -> new CustomException(UserErrorCode.USER_NOT_FOUND));
        user.updateLastLoginAt();

        // 4. 토큰 발급
        String accessToken = jwtProvider.createAccessToken(user);

        return new LoginResponse(accessToken, "Bearer", user.getUsername(), user.getRole());
    }

}