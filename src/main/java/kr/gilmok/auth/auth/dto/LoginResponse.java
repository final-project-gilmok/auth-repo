package kr.gilmok.auth.auth.dto;

public record LoginResponse(
        long accessTokenExpiresIn,
        String username,
        String role
) {
}
