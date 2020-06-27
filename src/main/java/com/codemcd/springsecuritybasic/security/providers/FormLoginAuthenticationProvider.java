package com.codemcd.springsecuritybasic.security.providers;

import com.codemcd.springsecuritybasic.domain.Account;
import com.codemcd.springsecuritybasic.domain.AccountRepository;
import com.codemcd.springsecuritybasic.security.AccountContext;
import com.codemcd.springsecuritybasic.security.AccountContextService;
import com.codemcd.springsecuritybasic.security.tokens.PostAuthorizationToken;
import com.codemcd.springsecuritybasic.security.tokens.PreAuthorizationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.NoSuchElementException;

public class FormLoginAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private AccountContextService accountContextService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AccountRepository accountRepository;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        PreAuthorizationToken token = (PreAuthorizationToken) authentication;

        String username = token.getUserName();
        String password = token.getUserPassword();

        Account account = accountRepository.findByUserId(username)
                .orElseThrow(() -> new NoSuchElementException("해당 아이디는 존재하지 않습니다."));

        if (isVerifiedPassword(password, account)) {
            return PostAuthorizationToken
                    .getTokenFromAccountContext(AccountContext.fromAccountModel(account));
        }

        throw new NoSuchElementException("인증 정보가 정확하지 않습니다.");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return PreAuthorizationToken.class.isAssignableFrom(authentication);
    }

    private boolean isVerifiedPassword(String password, Account account) {
        return passwordEncoder.matches(account.getPassword(), password);
    }
}
