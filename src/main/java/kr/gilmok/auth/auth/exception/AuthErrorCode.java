package kr.gilmok.auth.auth.exception;

import kr.gilmok.common.exception.ErrorCode;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public enum AuthErrorCode implements ErrorCode {
    /**
     * 유저 관련 에러 (AU)
     */
    DUPLICATE_USERNAME(HttpStatus.CONFLICT, "AU001", "이미 존재하는 아이디입니다."),
    PASSWORD_MISMATCH(HttpStatus.BAD_REQUEST, "AU002", "비밀번호가 일치하지 않습니다."),
    USER_NOT_FOUND(HttpStatus.NOT_FOUND, "AU003", "존재하지 않는 유저입니다."),

    /**
     * 토큰 관련 에러 (AT)
     */
    INVALID_REFRESH_TOKEN(HttpStatus.UNAUTHORIZED, "AT001", "유효하지 않은 리프레시 토큰입니다."),
    REFRESH_TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED, "AT002", "리프레시 토큰이 만료되었습니다. 다시 로그인해주세요."),
    NO_REFRESH_TOKEN(HttpStatus.BAD_REQUEST, "AT003", "리프레시 토큰이 존재하지 않습니다."),
    ;

    private final HttpStatus httpStatus;
    private final String code;
    private final String message;
}
