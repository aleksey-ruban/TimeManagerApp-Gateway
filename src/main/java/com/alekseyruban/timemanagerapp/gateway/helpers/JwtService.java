package com.alekseyruban.timemanagerapp.gateway.helpers;

import com.alekseyruban.timemanagerapp.gateway.exception.ApiException;
import com.alekseyruban.timemanagerapp.gateway.exception.ErrorCode;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Service
public class JwtService {

    private final SecretKey secretKey;

    public JwtService(@Value("${JWT_SECRET}") String secret) {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public Claims extractClaims(String token) {
        Claims claims = parseToken(token);
        Date expiration = claims.getExpiration();

        if (expiration != null && expiration.before(new Date())) {
            throw new ApiException(
                    HttpStatus.UNAUTHORIZED,
                    ErrorCode.INVALID_ACCESS_TOKEN,
                    "Invalid access token"
            );
        }
        return claims;
    }

    public Long extractUserId(Claims claims) {
        return Long.valueOf(claims.getSubject());
    }

    public Long extractSessionId(Claims claims) {
        return claims.get("sessionId", Long.class);
    }

    private Claims parseToken(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
