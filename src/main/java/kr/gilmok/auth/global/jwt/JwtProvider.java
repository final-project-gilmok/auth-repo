package kr.gilmok.auth.global.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import kr.gilmok.auth.auth.entity.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.UUID;

@Component
public class JwtProvider implements TokenProvider {

    @Value("${app.jwt.secret}")
    private String secretKey;

    @Value("${app.jwt.access-expiration-ms}")
    private long accessExpTime;

    @Value("${app.jwt.refresh-expiration-ms}")
    private long refreshExpTime;

    private Key key;

    @PostConstruct
    protected void init() {
        this.key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public String createAccessToken(User user) {
        Claims claims = Jwts.claims().setSubject(user.getUsername());
        claims.put("id", user.getId());
        claims.put("status", user.getStatus());
        claims.put("role", user.getRole());

        return buildToken(claims, accessExpTime, UUID.randomUUID().toString());
    }

    @Override
    public String createRefreshToken(User user) {
        Claims claims = Jwts.claims().setSubject(user.getUsername());
        claims.put("id", user.getId());

        return buildToken(claims, refreshExpTime, null);
    }

    // access token에만 jti가 존재하며, logout 시 blocklist 등록에 사용됨
    public String getJti(String token) {
        return parseClaims(token).getId();
    }

    // 토큰의 남은 유효시간(밀리초)을 반환함
    // blocklist TTL 설정에 사용됨
    public long getRemainingTtlMs(String token) {
        Date expiration = parseClaims(token).getExpiration();
        long remaining = expiration.getTime() - System.currentTimeMillis();
        return Math.max(remaining, 0L);
    }

    private Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private String buildToken(Claims claims, long expTime, String jti) {
        Date now = new Date();
        var builder = Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + expTime))
                .signWith(key, SignatureAlgorithm.HS256);

        if (jti != null) {
            builder.setId(jti);
        }

        return builder.compact();
    }
}
