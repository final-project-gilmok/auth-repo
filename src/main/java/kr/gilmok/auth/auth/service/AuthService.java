package kr.gilmok.auth.auth.service;

import io.micrometer.core.instrument.MeterRegistry;
import kr.gilmok.auth.auth.dto.AuthTokenDto;
import kr.gilmok.auth.auth.dto.LoginRequest;
import kr.gilmok.auth.auth.dto.SignupRequest;
import kr.gilmok.auth.auth.entity.AuthSession;
import kr.gilmok.auth.auth.entity.User;
import kr.gilmok.auth.auth.exception.AuthErrorCode;
import kr.gilmok.auth.auth.repository.AuthSessionRepository;
import kr.gilmok.auth.auth.repository.UserRepository;
import kr.gilmok.auth.global.jwt.JwtProvider;
import kr.gilmok.auth.global.jwt.TokenProvider;
import kr.gilmok.auth.global.util.TokenHashEncoder;
import kr.gilmok.common.exception.CustomException;
import kr.gilmok.common.exception.GlobalErrorCode;
import kr.gilmok.common.security.AccessTokenBlocklistRepository;
import kr.gilmok.common.security.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Slf4j
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final AuthSessionRepository authSessionRepository;
    private final AuthenticationManager authenticationManager;
    private final TokenHashEncoder tokenHashEncoder;
    private final AuthSessionService authSessionService;
    private final MeterRegistry meterRegistry;
    private final AccessTokenBlocklistRepository accessTokenBlocklistRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;
    private final TokenProvider tokenProvider;

    @Value("${app.jwt.access-expiration-ms}")
    private long accessExpTime;

    @Transactional
    public void signup(SignupRequest request) {
        validatePasswordMatch(request.password(), request.passwordConfirm());
        validateDuplicateUsername(request.username());

        String encodedPassword = passwordEncoder.encode(request.password());
        User user = User.createNewUser(request.username(), encodedPassword);

        userRepository.save(user);
        log.info("회원가입 완료 - username: {}", user.getUsername());
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
    public AuthTokenDto login(LoginRequest request, String ip, String userAgent) {
        Authentication authentication;

        try {
            // 1. Spring Security 표준 인증 시도
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.username(), request.password()));
        } catch (AuthenticationException e) {
            // 로그인 실패 메트릭 증가
            meterRegistry.counter("auth.login.failure").increment();
            log.warn("로그인 실패 - username: {}, reason: {}", request.username(), e.getMessage());

            // Spring Security의 예외를 우리의 CustomException으로 예쁘게 변환
            if (e instanceof UsernameNotFoundException || e.getCause() instanceof UsernameNotFoundException) {
                throw new CustomException(AuthErrorCode.USER_NOT_FOUND);
            } else if (e instanceof BadCredentialsException) {
                throw new CustomException(AuthErrorCode.PASSWORD_MISMATCH);
            }

            throw new CustomException(GlobalErrorCode.INVALID_USER);
        }

        // 2. 인증 성공시 유저 정보 추출
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        Long userId = userDetails.user().id();

        // 3. 접속 시간 업데이트
        User user = userRepository.getReferenceById(userId);
        user.updateLastLoginAt();

        // 4. 토큰 발급 (DIP 적용)
        String accessToken = tokenProvider.createAccessToken(user);
        String refreshToken = tokenProvider.createRefreshToken(user);

        authSessionService.saveSession(user, refreshToken, ip, userAgent);

        // 로그인 및 세션 발급 완료 시 성공 메트릭 증가
        meterRegistry.counter("auth.login.success").increment();
        log.info("로그인 성공 - username: {}, ip: {}", user.getUsername(), ip);

        return new AuthTokenDto(accessExpTime, accessToken, refreshToken, user.getUsername(), user.getRole());
    }

    // 재발급 (RTR): 기존 세션 무효화 후 새 토큰/세션 발급
    @Transactional
    public AuthTokenDto reissue(String oldRefreshToken, String ip, String userAgent) {
        // 1. 토큰 해싱 후 DB 조회
        String oldHash = tokenHashEncoder.encode(oldRefreshToken);
        AuthSession oldSession = authSessionRepository.findByRefreshTokenHashAndActive(oldHash)
                .orElseThrow(() -> {
                    log.warn("재발급 실패 - 유효하지 않은 리프레시 토큰 시도 (ip: {})", ip);
                    return new CustomException(AuthErrorCode.INVALID_REFRESH_TOKEN);
                });

        // 2. 만료 여부 확인 (DDD 관점: Entity에 행위 위임)
        oldSession.validateExpiration(LocalDateTime.now());

        // 3. 기존 세션 무효화
        oldSession.revoke();
        authSessionRepository.flush();

        // 4. 새로운 토큰 및 세션 생성
        User user = oldSession.getUser();
        String newAccessToken = tokenProvider.createAccessToken(user);
        String newRefreshToken = tokenProvider.createRefreshToken(user);

        authSessionService.saveSession(user, newRefreshToken, ip, userAgent);

        log.info("토큰 재발급 성공 - username: {}, ip: {}", user.getUsername(), ip);

        return new AuthTokenDto(accessExpTime, newAccessToken, newRefreshToken, user.getUsername(), user.getRole());
    }

    @Transactional
    public void logout(String accessToken, String refreshToken) {
        // 1. refresh token 세션 revoke
        if (refreshToken != null && !refreshToken.isBlank()) {
            String hash = tokenHashEncoder.encode(refreshToken);
            authSessionRepository.findByRefreshTokenHashAndActive(hash)
                    .ifPresent(session -> {
                        session.revoke();
                        log.info("로그아웃 - refresh 세션 무효화 완료");
                    });
        }

        // 2. access token jti 블랙리스트 등록
        if (accessToken != null && !accessToken.isBlank()) {
            try {
                String jti = jwtProvider.getJti(accessToken);
                long remainingTtlMs = jwtProvider.getRemainingTtlMs(accessToken);

                if (jti != null && remainingTtlMs > 0) {
                    accessTokenBlocklistRepository.block(jti, remainingTtlMs);
                    log.info("로그아웃 - access token blocklist 등록 완료 (ttlMs: {})", remainingTtlMs);
                }
            } catch (Exception e) {
                // 이미 만료된 토큰이거나 파싱 실패 시 무시 (이미 무효한 토큰이므로 등록 불요)
                log.debug("로그아웃 - access token 파싱 실패 (이미 만료된 토큰일 수 있음): {}", e.getMessage());
            }
        }

        log.info("로그아웃 처리 완료");
    }
}