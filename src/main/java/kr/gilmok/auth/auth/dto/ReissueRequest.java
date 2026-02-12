package kr.gilmok.auth.auth.dto;

import jakarta.validation.constraints.NotBlank;

public record ReissueRequest(
        @NotBlank(message = "refresh token 값은 필수입니다.")
        String refreshToken
) {
}
