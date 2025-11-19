package com.alekseyruban.timemanagerapp.gateway.client;

import com.alekseyruban.timemanagerapp.gateway.DTO.TokenValidationRequest;
import com.alekseyruban.timemanagerapp.gateway.DTO.TokenValidationResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class AuthServiceClient {

    private final WebClient authWebClient;

    public Mono<Boolean> validateToken(Long sessionId, String token) {
        TokenValidationRequest request = new TokenValidationRequest(sessionId, token);
        return authWebClient.post()
                .uri("/internal/validate-access-token")
                .bodyValue(request)
                .retrieve()
                .bodyToMono(TokenValidationResponse.class)
                .map(TokenValidationResponse::getValid)
                .onErrorReturn(false);
    }
}