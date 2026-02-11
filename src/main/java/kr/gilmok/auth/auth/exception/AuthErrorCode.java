package kr.gilmok.auth.auth.exception;

import kr.gilmok.common.exception.ErrorCode;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public enum AuthErrorCode implements ErrorCode {
    DUPLICATE_USERNAME(HttpStatus.CONFLICT, "U001", "이미 존재하는 아이디입니다."),
    PASSWORD_MISMATCH(HttpStatus.BAD_REQUEST, "U002", "비밀번호가 일치하지 않습니다."),
    USER_NOT_FOUND(HttpStatus.NOT_FOUND, "U003", "존재하지 않는 유저입니다."),
    ;

    private final HttpStatus httpStatus;
    private final String code;
    private final String message;
}
