package com.codemcd.springsecuritybasic.security.handlers;

import com.codemcd.springsecuritybasic.dtos.TokenDto;
import com.codemcd.springsecuritybasic.security.AccountContext;
import com.codemcd.springsecuritybasic.security.JwtFactory;
import com.codemcd.springsecuritybasic.security.tokens.PostAuthorizationToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class FormLoginAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    @Autowired
    private JwtFactory factory;

    @Autowired
    private ObjectMapper mapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {
        PostAuthorizationToken token = (PostAuthorizationToken) authentication;
        AccountContext context = (AccountContext) token.getPrincipal();

        String jwt = factory.generateToken(context);

        processResponse(response, writeDto(jwt));
    }

    private TokenDto writeDto(String token) {
        return new TokenDto(token);
    }

    private void processResponse(HttpServletResponse response, TokenDto dto) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpStatus.OK.value());
        response.getWriter().write(mapper.writeValueAsString(dto));
    }
}
