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
        String ip = httpRequest.getRemoteAddr();
        String userAgent = normalizeUserAgent(httpRequest.getHeader("User-Agent"));

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

        String ip = httpRequest.getRemoteAddr();
        String userAgent = normalizeUserAgent(httpRequest.getHeader("User-Agent"));

        AuthTokenDto tokenDto = authService.reissue(refreshToken, ip, userAgent);

        addTokenCookies(httpResponse, tokenDto);

        return ResponseEntity.ok(ApiResponse.success(toLoginResponse(tokenDto)));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<String>> logout(
            @CookieValue(value = "accessToken", required = false) String accessToken,
            @CookieValue(value = "refreshToken", required = false) String refreshToken,
            HttpServletResponse httpResponse) {
        authService.logout(accessToken, refreshToken);

        // 쿠키 즉시 만료
        httpResponse.addHeader(HttpHeaders.SET_COOKIE, expireCookie("accessToken").toString());
        httpResponse.addHeader(HttpHeaders.SET_COOKIE, expireCookie("refreshToken").toString());

        return ResponseEntity.ok(ApiResponse.success("로그아웃 완료"));
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
                .secure(false)
                .path("/")
                .maxAge(expTime / 1000)
                .sameSite("Lax")
                .build();
    }

    private ResponseCookie expireCookie(String name) {
        return ResponseCookie.from(name, "")
                .httpOnly(true)
                .secure(false)
                .path("/")
                .maxAge(0)
                .sameSite("Lax")
                .build();
    }

    private String normalizeUserAgent(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) {
            return "Unknown";
        }
        return userAgent;
    }

    private LoginResponse toLoginResponse(AuthTokenDto tokenDto) {
        return new LoginResponse(
                tokenDto.accessTokenExpiresIn(),
                tokenDto.username(),
                tokenDto.role());
    }
}
