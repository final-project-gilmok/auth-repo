package kr.gilmok.auth.global.config;

import jakarta.servlet.Filter;
import kr.gilmok.common.filter.JwtAuthenticationFilter;
import kr.gilmok.common.security.AccessTokenBlocklistFilter;
import kr.gilmok.common.security.CommonSecurityConfig;
import kr.gilmok.common.security.CustomAuthenticationEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends CommonSecurityConfig {

    private final AccessTokenBlocklistFilter accessTokenBlocklistFilter;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,
                          CustomAuthenticationEntryPoint customAuthenticationEntryPoint,
                          AccessTokenBlocklistFilter accessTokenBlocklistFilter) {
        super(jwtAuthenticationFilter, customAuthenticationEntryPoint);
        this.accessTokenBlocklistFilter = accessTokenBlocklistFilter;
    }

    @Override
    protected void configureRequestMatchers(
            AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry auth) {
        auth.requestMatchers("/auth/signup", "/auth/login", "/auth/reissue").permitAll()
                .requestMatchers(HttpMethod.GET, "/actuator/prometheus", "/actuator/health").permitAll()
                .requestMatchers("/auth/logout").authenticated()
                .requestMatchers("/error").permitAll();
    }

    // JwtAuthenticationFilter 이후에 블랙리스트 체크 필터를 등록
    // 로그아웃된 access token의 jti를 Redis에서 확인하여 차단
    @Override
    protected List<Filter> getFiltersAfterJwtAuthentication() {
        return List.of(accessTokenBlocklistFilter);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}
