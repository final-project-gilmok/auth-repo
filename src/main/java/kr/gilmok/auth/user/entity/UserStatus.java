package kr.gilmok.auth.user.entity;

import lombok.Getter;

@Getter
public enum UserStatus {
    ACTIVE("활성"),
    LOCKED("잠김"),
    DELETED("삭제");

    private final String description;

    UserStatus(String description) {
        this.description = description;
    }
}