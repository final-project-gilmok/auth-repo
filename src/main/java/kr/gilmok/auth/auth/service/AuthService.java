package kr.gilmok.auth.auth.service;

import kr.gilmok.auth.auth.dto.LoginRequest;
import kr.gilmok.auth.auth.dto.LoginResponse;
import kr.gilmok.auth.auth.dto.SignupRequest;
import kr.gilmok.auth.auth.dto.TokenResponse;
import kr.gilmok.auth.auth.entity.AuthSession;
import kr.gilmok.auth.auth.entity.User;
import kr.gilmok.auth.auth.exception.AuthErrorCode;
import kr.gilmok.auth.auth.repository.AuthSessionRepository;
import kr.gilmok.auth.auth.repository.UserRepository;
import kr.gilmok.auth.global.Jwt.JwtProvider;
import kr.gilmok.auth.global.util.HashUtil;
import kr.gilmok.common.exception.CustomException;
import kr.gilmok.common.security.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final AuthSessionRepository authSessionRepository;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;
    private final AuthSessionService authSessionService;

    @Value("${app.jwt.access-expiration-ms}")
    private long accessExpTime;

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
            throw new CustomException(AuthErrorCode.PASSWORD_MISMATCH);
        }
    }

    private void validateDuplicateUsername(String username) {
        userRepository.findByUsername(username).ifPresent(user -> {
            throw new CustomException(AuthErrorCode.DUPLICATE_USERNAME);
        });
    }

    @Transactional
    public LoginResponse login(LoginRequest request, String ip, String userAgent) {
        // 1. Spring Security 표준 인증 시도
        Authentication authentication = authenticationManager.authenticate( // -> CustomUserDetailsService 실행
                new UsernamePasswordAuthenticationToken(request.username(), request.password())
        );

        // 2. 인증 성공시 유저 정보 추출
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        Long userId = userDetails.user().id();

        // 3. 접속 시간 업데이트
        User user = userRepository.getReferenceById(userId);
        user.updateLastLoginAt();

        // 4. 토큰 발급
        String accessToken = jwtProvider.createAccessToken(user);
        String refreshToken = jwtProvider.createRefreshToken(user);

        authSessionService.saveSession(user, refreshToken, ip, userAgent);

        return new LoginResponse(accessToken, refreshToken, accessExpTime, "Bearer", user.getUsername(), user.getRole());
    }

    // 재발급 (RTR): 기존 세션 무효화 후 새 토큰/세션 발급
    @Transactional
    public TokenResponse reissue(String oldRefreshToken, String ip, String userAgent) {
        // 1. 토큰 해싱 후 DB 조회
        String oldHash = HashUtil.hash(oldRefreshToken);
        AuthSession oldSession = authSessionRepository.findByRefreshTokenHashAndActive(oldHash)
                .orElseThrow(() -> new CustomException(AuthErrorCode.INVALID_REFRESH_TOKEN));

        // 2. 만료 여부 확인
        if (oldSession.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new CustomException(AuthErrorCode.REFRESH_TOKEN_EXPIRED);
        }

        // 3. 기존 세션 무효화
        oldSession.revoke();

        // 4. 새로운 토큰 및 세션 생성
        User user = oldSession.getUser();
        String newAccessToken = jwtProvider.createAccessToken(user);
        String newRefreshToken = jwtProvider.createRefreshToken(user);

        authSessionService.saveSession(user, newRefreshToken, ip, userAgent);

        return new TokenResponse(newAccessToken, newRefreshToken, "Bearer");
    }
}