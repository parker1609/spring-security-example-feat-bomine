package com.codemcd.springsecuritybasic.security;

import com.codemcd.springsecuritybasic.domain.Account;
import com.codemcd.springsecuritybasic.domain.UserRole;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class AccountContext extends User {

    private AccountContext(String username,
                           String password,
                           Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
    }

    public static AccountContext fromAccountModel(Account account) {
        return new AccountContext(account.getUsername(),
                account.getPassword(), parseAuthorities(account.getUserRole()));
    }

    private static List<SimpleGrantedAuthority> parseAuthorities(UserRole role) {
        return Stream.of(role)
                .map(r -> new SimpleGrantedAuthority(r.getName()))
                .collect(Collectors.toList())
                ;
    }
}
