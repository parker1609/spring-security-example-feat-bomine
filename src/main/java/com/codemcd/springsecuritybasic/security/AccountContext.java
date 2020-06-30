package com.codemcd.springsecuritybasic.security;

import com.codemcd.springsecuritybasic.domain.Account;
import com.codemcd.springsecuritybasic.domain.UserRole;
import com.codemcd.springsecuritybasic.security.tokens.JwtPostProcessingToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class AccountContext extends User {

    private AccountContext(String userId,
                           String password,
                           Collection<? extends GrantedAuthority> authorities) {
        super(userId, password, authorities);
    }

    public AccountContext(String userId, String password, String role) {
        this(userId, password, parseAuthorities(role));
    }

    public static AccountContext fromAccountModel(Account account) {
        return new AccountContext(account.getUsername(),
                account.getPassword(), parseAuthorities(account.getUserRole()));
    }

    public static AccountContext fromJwtPostToken(JwtPostProcessingToken token) {
        return new AccountContext(token.getUserId(), token.getPassword(), token.getAuthorities());
    }

    private static List<SimpleGrantedAuthority> parseAuthorities(UserRole role) {
        return Stream.of(role)
                .map(r -> new SimpleGrantedAuthority(r.getName()))
                .collect(Collectors.toList())
                ;
    }

    private static List<SimpleGrantedAuthority> parseAuthorities(String roleName) {
        return parseAuthorities(UserRole.of(roleName));
    }
}
