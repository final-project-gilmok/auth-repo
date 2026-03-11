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
public class AuthSignUpConcurrencyTest {

    @Autowired
    private AuthService authService;

    @Test
    @DisplayName("동일한 아이디로 동시에 10명이 가입을 시도하면 1명만 성공해야 한다")
    void signup_concurrency_test() throws InterruptedException {
        // given
        int threadCount = 10;
        ExecutorService executorService = Executors.newFixedThreadPool(32);
        CountDownLatch readyLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);

        SignupRequest request = new SignupRequest("duplicateUser", "password123!", "password123!");

        AtomicInteger successCount = new AtomicInteger();
        AtomicInteger failCount = new AtomicInteger();

        // when
        for (int i = 0; i < threadCount; i++) {
            executorService.execute(() -> {
                try {
                    readyLatch.await(); // 대기
                    authService.signup(request);
                    successCount.getAndIncrement();
                } catch (Exception e) {
                    failCount.getAndIncrement();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        readyLatch.countDown(); // 시작 신호
        doneLatch.await(); // 모든 스레드의 작업이 끝날 때까지 대기
        executorService.shutdown();

        // then
        assertEquals(1, successCount.get(), "성공한 가입은 1건이어야 합니다.");
        assertEquals(threadCount - 1, failCount.get(), "나머지 시도는 모두 실패해야 합니다.");
    }
}
