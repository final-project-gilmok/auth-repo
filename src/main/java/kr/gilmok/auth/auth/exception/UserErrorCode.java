package kr.gilmok.auth.auth.exception;

import kr.gilmok.common.exception.ErrorCode;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public enum UserErrorCode implements ErrorCode {
    DUPLICATE_USERNAME(HttpStatus.CONFLICT, "U001", "이미 존재하는 아이디입니다.");

    private final HttpStatus httpStatus;
    private final String code;
    private final String message;
}
