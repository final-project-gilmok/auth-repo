package kr.gilmok.auth.auth.dto;

public record LoginResponse(
        long accessTokenExpiresIn,
        String username,
        String role,
        String accessToken  // Swagger Authorize용 (httpOnly 쿠키는 JS에서 읽을 수 없어 body에도 포함)
) {
}
