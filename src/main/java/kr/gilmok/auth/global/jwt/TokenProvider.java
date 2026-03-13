package kr.gilmok.auth.global.jwt;

import kr.gilmok.auth.auth.entity.User;

public interface TokenProvider {
    String createAccessToken(User user);

    String createRefreshToken(User user);
}
