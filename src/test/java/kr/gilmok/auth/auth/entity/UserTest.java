package kr.gilmok.auth.auth.entity;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class UserTest {

    @Test
    @DisplayName("관리자 계정 생성 시 ROLE_ADMIN 권한이 부여되어야 한다")
    void createAdmin_shouldHaveAdminRole() {
        // given
        String username = "adminUser";
        String password = "encodedPassword";

        // when: 정적 팩토리 메서드를 통해 관리자 생성
        User admin = User.createAdmin(username, password);

        // then
        assertNotNull(admin);
        assertEquals(username, admin.getUsername());

        // "ROLE_USER"가 아닌 "ROLE_ADMIN"이어야 함
        assertEquals("ROLE_ADMIN", admin.getRole());
        assertEquals(UserStatus.ACTIVE, admin.getStatus());
    }

    @Test
    @DisplayName("일반 유저 생성 시 ROLE_USER 권한이 부여되어야 한다")
    void createNewUser_shouldHaveUserRole() {
        // when
        User user = User.createNewUser("regularUser", "password");

        // then
        assertEquals("ROLE_USER", user.getRole());
        assertEquals(UserStatus.ACTIVE, user.getStatus());
    }
}
