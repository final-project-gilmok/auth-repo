package kr.gilmok.auth.global.Jwt;

import kr.gilmok.auth.auth.entity.User;

public interface TokenProvider {
    String createAccessToken(User user);

    String createRefreshToken(User user);
}
