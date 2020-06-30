package com.codemcd.springsecuritybasic.security;

import com.codemcd.springsecuritybasic.domain.Account;
import com.codemcd.springsecuritybasic.domain.UserRole;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ExtendWith(SpringExtension.class)
public class JwtFactoryTest {
    private static final Logger log = LoggerFactory.getLogger(JwtFactoryTest.class);

    private AccountContext context;

    @Autowired
    private JwtFactory factory;

    @BeforeEach
    void setUp() {
        Account account = Account.builder()
                .username("park")
                .userId("codemcd")
                .password("1234")
                .userRole(UserRole.USER).build();
        context = AccountContext.fromAccountModel(account);
    }

    @Test
    @DisplayName("JWT 토큰이 정상적으로 생성되는지 확인한다.")
    void jwt_generation() {
        String token = factory.generateToken(context);

        assertThat(token).isNotNull();

        log.info(token);
    }

    @Test
    void name() {

    }

    @AfterEach
    void tearDown() {

    }
}
