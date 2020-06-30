package com.codemcd.springsecuritybasic;

import com.codemcd.springsecuritybasic.domain.Account;
import com.codemcd.springsecuritybasic.domain.AccountRepository;
import com.codemcd.springsecuritybasic.domain.UserRole;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class SpringSecurityBasicApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityBasicApplication.class, args);
    }

    @Bean
    CommandLineRunner bootStrapTest(AccountRepository repository, PasswordEncoder encoder) {
        return args -> {
            Account account = Account.builder()
                    .userId("codemcd")
                    .username("park")
                    .password(encoder.encode("1234"))
                    .userRole(UserRole.USER).build();

            repository.save(account);
        };
    }
}
