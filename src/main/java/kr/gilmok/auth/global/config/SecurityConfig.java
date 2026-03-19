package kr.gilmok.auth.global.config;

import jakarta.servlet.Filter;
import kr.gilmok.common.filter.JwtAuthenticationFilter;
import kr.gilmok.common.security.AccessTokenBlocklistFilter;
import kr.gilmok.common.security.CommonSecurityConfig;
import kr.gilmok.common.security.CustomAuthenticationEntryPoint;
import org.springframework.beans.factory.annotation.Value;
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

    @Value("${app.swagger.enabled:false}")
    private boolean swaggerEnabled;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,
                          CustomAuthenticationEntryPoint customAuthenticationEntryPoint,
                          AccessTokenBlocklistFilter accessTokenBlocklistFilter) {
        super(jwtAuthenticationFilter, customAuthenticationEntryPoint);
        this.accessTokenBlocklistFilter = accessTokenBlocklistFilter;
    }

    @Override
    protected void configureRequestMatchers(
            AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry auth) {
        auth.requestMatchers("/v3/api-docs", "/v3/api-docs/**").permitAll();
        if (swaggerEnabled) {
            auth.requestMatchers("/swagger-ui.html", "/swagger-ui/**").permitAll();
        }
        auth
                .requestMatchers("/auth/signup", "/auth/login", "/auth/reissue").permitAll()
                .requestMatchers(HttpMethod.GET, "/actuator/prometheus", "/actuator/health").permitAll()
                .requestMatchers("/error").permitAll();  // 404 등 에러 응답 시 forward되는 경로
    }

    // JwtAuthenticationFilter 이후에 블랙리스트 체크 필터를 등록
    // 로그아웃된 access token의 jti를 Redis에서 확인하여 차단
    @Override
    protected List<Filter> getFiltersAfterJwtAuthentication() {
        return List.of(accessTokenBlocklistFilter);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(8);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}
