package kr.gilmok.auth.auth.dto;

public record AuthTokenDto(
        long accessTokenExpiresIn,
        String accessToken,
        String refreshToken,
        String username,
        String role
) {
}