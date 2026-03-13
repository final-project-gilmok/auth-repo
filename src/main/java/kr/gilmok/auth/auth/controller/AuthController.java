package kr.gilmok.auth.auth.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kr.gilmok.auth.auth.dto.AuthTokenDto;
import kr.gilmok.auth.auth.dto.LoginRequest;
import kr.gilmok.auth.auth.dto.LoginResponse;
import kr.gilmok.auth.auth.dto.SignupRequest;
import kr.gilmok.auth.auth.exception.AuthErrorCode;
import kr.gilmok.auth.auth.service.AuthService;
import kr.gilmok.common.dto.ApiResponse;
import kr.gilmok.common.exception.CustomException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @Value("${app.jwt.access-expiration-ms}")
    private long accessExpTime;

    @Value("${app.jwt.refresh-expiration-ms}")
    private long refreshExpTime;

    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<String>> signup(@Validated @RequestBody SignupRequest request) {
        authService.signup(request);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(ApiResponse.success("회원가입 완료"));
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(@Validated @RequestBody LoginRequest request,
            HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        String ip = extractClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");
        if (userAgent != null && userAgent.isBlank()) {
            userAgent = null;
        }

        AuthTokenDto tokenDto = authService.login(request, ip, userAgent);

        addTokenCookies(httpResponse, tokenDto);

        return ResponseEntity.ok(ApiResponse.success(toLoginResponse(tokenDto)));
    }

    @PostMapping("/reissue")
    public ResponseEntity<ApiResponse<LoginResponse>> reissue(
            @CookieValue(value = "refreshToken", required = false) String refreshToken,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new CustomException(AuthErrorCode.NO_REFRESH_TOKEN);
        }

        String ip = extractClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");
        if (userAgent == null || userAgent.isBlank()) {
            userAgent = "Unknown";
        }

        AuthTokenDto tokenDto = authService.reissue(refreshToken, ip, userAgent);

        addTokenCookies(httpResponse, tokenDto);

        return ResponseEntity.ok(ApiResponse.success(toLoginResponse(tokenDto)));
    }

    private void addTokenCookies(HttpServletResponse response, AuthTokenDto tokenDto) {
        ResponseCookie accessTokenCookie = createTokenCookie("accessToken", tokenDto.accessToken(),
                accessExpTime);
        ResponseCookie refreshTokenCookie = createTokenCookie("refreshToken", tokenDto.refreshToken(),
                refreshExpTime);

        response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());
    }

    private ResponseCookie createTokenCookie(String name, String value, long expTime) {
        return ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(false) // HTTPS 전용
                .path("/")
                .maxAge(expTime / 1000)
                .sameSite("Lax")
                .build();
    }

    private LoginResponse toLoginResponse(AuthTokenDto tokenDto) {
        return new LoginResponse(
                tokenDto.accessTokenExpiresIn(),
                tokenDto.username(),
                tokenDto.role());
    }

    private String extractClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isBlank() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("X-Real-IP");
        }
        if (ip == null || ip.isBlank() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }
        return ip;
    }
}
