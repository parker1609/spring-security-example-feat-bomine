package com.codemcd.springsecuritybasic.security;

import com.codemcd.springsecuritybasic.domain.Account;
import com.codemcd.springsecuritybasic.domain.AccountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.NoSuchElementException;

@Component
public class AccountContextService implements UserDetailsService {

    @Autowired
    private AccountRepository accountRepository;

    @Override
    public UserDetails loadUserByUsername(String userId) throws UsernameNotFoundException {
        Account account = accountRepository.findByUserId(userId)
                .orElseThrow(() -> new NoSuchElementException("해당 아이디는 존재하지 않습니다."));

        return AccountContext.fromAccountModel(account);
    }
}
