package com.codemcd.springsecuritybasic.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.NoSuchElementException;
import java.util.stream.Stream;

@AllArgsConstructor
@Getter
public enum UserRole {
    ADMIN("ROLE_ADMIN"),
    USER("ROLE_USER");

    private String name;

    private boolean isCorrectName(String name) {
        return name.equalsIgnoreCase(this.name);
    }

    public static UserRole of(String name) {
        return Stream.of(UserRole.values())
                .filter(role -> role.isCorrectName(name))
                .findAny()
                .orElseThrow(() -> new NoSuchElementException("검색된 권한이 없습니다."))
                ;
    }
}
