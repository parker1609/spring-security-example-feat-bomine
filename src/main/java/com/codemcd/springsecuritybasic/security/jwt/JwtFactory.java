package com.codemcd.springsecuritybasic.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.codemcd.springsecuritybasic.security.AccountContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class JwtFactory {
    private static final Logger log = LoggerFactory.getLogger(JwtFactory.class);
    private static String signingKey = "jwttest";

    public String generateToken(AccountContext context) {
        String token = null;
        List<GrantedAuthority> authorities = new ArrayList<>(context.getAuthorities());

        try {
            token = JWT.create()
                    .withIssuer("codemcd")
                    .withClaim("USERNAME", context.getUsername())
                    .withClaim("USER_ROLE", authorities.get(0).getAuthority())
                    .sign(generateAlgorithm());
        } catch (Exception e) {
            log.error(e.getMessage());
        }

        return token;
    }

    private Algorithm generateAlgorithm() {
        return Algorithm.HMAC256(signingKey);
    }
}
