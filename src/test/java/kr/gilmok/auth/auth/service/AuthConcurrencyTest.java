package kr.gilmok.auth.auth.service;

import kr.gilmok.auth.auth.dto.SignupRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
@ActiveProfiles("test")
public class AuthConcurrencyTest {

    @Autowired
    private AuthService authService;

    @Test
    @DisplayName("동일한 아이디로 동시에 10명이 가입을 시도하면 1명만 성공해야 한다")
    void signup_concurrency_test() throws InterruptedException {
        // given
        int threadCount = 10;
        ExecutorService executorService = Executors.newFixedThreadPool(32);
        CountDownLatch latch = new CountDownLatch(threadCount); // 모든 스레드가 동시에 시작하도록 대기

        SignupRequest request = new SignupRequest("duplicateUser", "password123!", "password123!");

        // 성공과 실패 카운트를 측정하기 위한 원자적 변수
        AtomicInteger successCount = new AtomicInteger();
        AtomicInteger failCount = new AtomicInteger();

        // when
        for (int i = 0; i < threadCount; i++) {
            executorService.execute(() -> {
                try {
                    authService.signup(request);
                    successCount.getAndIncrement();
                } catch (Exception e) {
                    failCount.getAndIncrement();
                } finally {
                    latch.countDown();
                }
            });
        }

        latch.await(); // 모든 스레드의 작업이 끝날 때까지 대기

        // then
        assertEquals(1, successCount.get(), "성공한 가입은 1건이어야 합니다.");
        assertEquals(threadCount - 1, failCount.get(), "나머지 시도는 모두 실패해야 합니다.");
    }
}
