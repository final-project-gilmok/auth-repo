package kr.gilmok.auth.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record SignupRequest(
        @NotBlank(message = "아이디는 필수입니다.")
        @Size(min = 2, max = 10, message = "아이디는 2~10자 사이여야 합니다.")
        String username,

        @NotBlank(message = "비밀번호는 필수입니다.")
        @Size(min = 8, message = "비밀번호는 최소 8자 이상이어야 합니다.")
        String password,

        @NotBlank(message = "비밀번호 확인을 입력해주세요.")
        String passwordConfirm
) {
}
