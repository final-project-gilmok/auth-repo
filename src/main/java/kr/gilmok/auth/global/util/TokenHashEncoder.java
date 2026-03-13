package kr.gilmok.auth.global.util;

public interface TokenHashEncoder {
    String encode(String rawToken);
}
