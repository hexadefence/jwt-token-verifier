package com.hexadefence.api.securityConfig;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

public class CustomSecurityFilter implements Filter {

    Logger logger = LoggerFactory.getLogger(getClass());

    JwkProvider jwkProvider;

    public CustomSecurityFilter() throws MalformedURLException {
        jwkProvider = new JwkProviderBuilder(new URL("http://localhost:8080/realms/master/protocol/openid-connect/certs")).build();
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        try {

            String authorizationHeader = ((HttpServletRequest) request).getHeader("Authorization");
            String token = authorizationHeader.substring(7);

            DecodedJWT decodedJWT = JWT.decode(token);

            // start verification process
            Jwk jwk = jwkProvider.get(decodedJWT.getKeyId());

            // Assuming all tokens are signed using RSA256 algorithm otherwise algorithm can be found using jwk.getAlgorithm() method
            Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);

            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer("http://localhost:8080/realms/master")
                    .withAudience("backend-api")
                    .build();
            verifier.verify(decodedJWT);

            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(decodedJWT.getSubject(), "***",
                            List.of(new SimpleGrantedAuthority("SIMPLE_AUTHORITY"))));



        } catch (JWTVerificationException jwtVerificationException){
            logger.error("Verification Exception", jwtVerificationException);
        }
        catch (Exception e){
            logger.error("Exception", e);
        }


        chain.doFilter(request, response);

        SecurityContextHolder.clearContext();

    }
}
