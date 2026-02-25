package kr.gilmok.auth.auth.service;

import kr.gilmok.auth.auth.entity.AuthSession;
import kr.gilmok.auth.auth.entity.User;
import kr.gilmok.auth.auth.repository.AuthSessionRepository;
import kr.gilmok.auth.auth.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
public class AuthSessionServiceConcurrencyTest {

    @Autowired
    private AuthSessionService authSessionService;

    @Autowired
    private AuthSessionRepository authSessionRepository;

    @Autowired
    private UserRepository userRepository;

    @Test
    @DisplayName("동시 세션 저장 요청 시 유니크 제약 조건과 Upsert 로직으로 인해 중복 데이터가 발생하지 않아야 한다")
    void saveSession_concurrencyTest() throws Exception {
        // given
        User user = User.createNewUser("concurrencyUser", "password");
        userRepository.saveAndFlush(user);
        Long userId = user.getId(); // 객체 대신 ID만 추출하여 스레드에 전달

        String ip = "192.168.0.1";
        String userAgent = "Mozilla/5.0";
        int threadCount = 10;

        ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
        CountDownLatch readyLatch = new CountDownLatch(1); // 동시 출발을 위한 신호탄
        CountDownLatch doneLatch = new CountDownLatch(threadCount); // 모든 작업 완료 대기

        // when
        for (int i = 0; i < threadCount; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    readyLatch.await(); // 모든 스레드가 여기서 대기하다가 신호가 오면 동시에 출발

                    // 각 스레드(트랜잭션)마다 독립적으로 User 엔티티를 조회해서 사용해야 안전함
                    User threadUser = userRepository.findById(userId).orElseThrow();
                    authSessionService.saveSession(threadUser, "token-" + index, ip, userAgent);

                } catch (Exception e) {
                    System.err.println("Thread Exception: " + e.getMessage());
                } finally {
                    doneLatch.countDown(); // 작업 완료 보고
                }
            });
        }

        readyLatch.countDown(); // 10개의 스레드에게 동시 출발 신호 발송
        doneLatch.await(); // 10개의 스레드가 모두 끝날 때까지 메인 스레드 대기
        executorService.shutdown();

        // then
        User finalUser = userRepository.findById(userId).orElseThrow();
        List<AuthSession> sessions = authSessionRepository.findAllActiveSessionsByUser(finalUser);

        // 여러 번의 동시 요청에도 불구하고, 활성 세션은 단 1개여야 함
        assertThat(sessions).hasSize(1);
    }
}