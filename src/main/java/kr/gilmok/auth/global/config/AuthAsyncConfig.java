package kr.gilmok.auth.global.config;

import kr.gilmok.auth.auth.exception.AuthErrorCode;
import kr.gilmok.common.exception.CustomException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.web.servlet.config.annotation.AsyncSupportConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class AuthAsyncConfig implements WebMvcConfigurer {

    @Bean(name = "authTaskExecutor")
    public ThreadPoolTaskExecutor authTaskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(20);
        executor.setMaxPoolSize(20);
        executor.setQueueCapacity(100);
        executor.setThreadNamePrefix("auth-async-");
        executor.setRejectedExecutionHandler((r, e) -> {
            throw new CustomException(AuthErrorCode.SERVER_BUSY);
        });
        return executor;
    }

    @Override
    public void configureAsyncSupport(AsyncSupportConfigurer configurer) {
        configurer.setDefaultTimeout(30000);
        configurer.setTaskExecutor(authTaskExecutor());
    }
}
