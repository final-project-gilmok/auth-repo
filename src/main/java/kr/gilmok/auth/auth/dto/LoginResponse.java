package kr.gilmok.auth.auth.dto;

public record LoginResponse(
        String accessToken,
        String tokenType,
        String username,
        String role
) {
}
