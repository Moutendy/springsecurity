package com.reseau.springsecurity.security.utils;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.reseau.springsecurity.model.UserModel;

public class JwtUtils {
    JwtUtils() {}
    // secret needs to be encoded and saved to db later
    private static final Algorithm ALGORITHM = Algorithm
            .HMAC256("?KQSDJàéà_ze&éàA2@11.2.1.???;:!.EZ.A218ZUAZJ".getBytes());



    public static Map<String, String> buildTokens(UserModel user, String issuer) {

        String username = user.getUsername();

        String accessToken = JWT.create().withSubject(username)
                .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 60 * 1000)).withIssuer(issuer)
                .withClaim("role", user.getRoles().getRoleName()).sign(ALGORITHM);

        String refreshToken = JWT.create().withSubject(username)
                .withExpiresAt(new Date(System.currentTimeMillis() + 5 * 60 * 60 * 1000)).withIssuer(issuer)
                .sign(ALGORITHM);

        Map<String, String> tokens = new HashMap<>();

        tokens.put("accessToken", accessToken);
        tokens.put("refreshToken", refreshToken);
        tokens.put("role", user.getRoles().getRoleName());
        tokens.put("username", username);

        return tokens;
    }

    public static DecodedJWT decodeToken(String token) {

        JWTVerifier verifier = JWT.require(ALGORITHM).build();

        return verifier.verify(token);
    }
}
