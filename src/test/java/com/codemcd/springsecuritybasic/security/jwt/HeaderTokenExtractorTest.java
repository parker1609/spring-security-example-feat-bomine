package com.codemcd.springsecuritybasic.security.jwt;

import com.codemcd.springsecuritybasic.security.exception.InvalidJwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class HeaderTokenExtractorTest {
    private HeaderTokenExtractor extractor = new HeaderTokenExtractor();
    private String header;

    @BeforeEach
    void setUp() {
        header = "Bearer header.payload.key";
    }

    @Test
    @DisplayName("정상적인 헤더에서 JWT를 추출한다.")
    void valid_jwt() {
        assertThat(extractor.extract(header)).isEqualTo("header.payload.key");
    }

    @Test
    @DisplayName("빈 헤더에서 JWT를 추출하려하면 예외가 발생한다.")
    void empty_header() {
        String invalidHeader = "";

        assertThatThrownBy(() -> extractor.extract(invalidHeader))
                .isInstanceOf(InvalidJwtException.class)
                .hasMessage("올바른 JWT 정보가 아닙니다!");
    }
}
