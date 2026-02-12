package kr.gilmok.auth.auth.dto;

public record LoginResponse(
        String accessToken,
        String refreshToken,
        long accessTokenExpiresIn,
        String tokenType,
        String username,
        String role
) {
}
