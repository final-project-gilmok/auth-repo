package kr.gilmok.auth.global.config;

import kr.gilmok.common.filter.JwtAuthenticationFilter;
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

@Configuration
@EnableWebSecurity
public class SecurityConfig extends CommonSecurityConfig {

    @Value("${app.swagger.enabled:false}")
    private boolean swaggerEnabled;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,
                          CustomAuthenticationEntryPoint customAuthenticationEntryPoint) {
        super(jwtAuthenticationFilter, customAuthenticationEntryPoint);
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

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(8);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}
