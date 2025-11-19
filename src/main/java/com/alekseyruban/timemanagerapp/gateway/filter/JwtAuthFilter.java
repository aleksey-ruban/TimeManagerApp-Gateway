package com.alekseyruban.timemanagerapp.gateway.filter;

import com.alekseyruban.timemanagerapp.gateway.client.AuthServiceClient;
import com.alekseyruban.timemanagerapp.gateway.config.CustomGatewayProperties;
import com.alekseyruban.timemanagerapp.gateway.exception.ErrorCode;
import com.alekseyruban.timemanagerapp.gateway.helpers.JwtService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter implements GlobalFilter, Ordered {

    private final AuthServiceClient authServiceClient;
    private final JwtService jwtService;
    private final CustomGatewayProperties gatewayProperties;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();

        if (gatewayProperties.getWhitelist().contains(path)) {
            return chain.filter(exchange);
        }

        String header = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = header.substring(7);

        Long sessionId;
        try {
            sessionId = jwtService.extractSessionId(token);
        } catch (Exception e) {
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

            Map<String, Object> bodyMap = Map.of(
                    "status", HttpStatus.UNAUTHORIZED.value(),
                    "error", ErrorCode.INVALID_ACCESS_TOKEN.name(),
                    "message", "Invalid access token",
                    "timestamp", LocalDateTime.now().toString()
            );

            try {
                ObjectMapper mapper = new ObjectMapper();
                byte[] bytes = mapper.writeValueAsBytes(bodyMap);
                DataBuffer buffer = response.bufferFactory().wrap(bytes);
                return response.writeWith(Mono.just(buffer));
            } catch (Exception er) {
                response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
                return response.setComplete();
            }
        }

        return authServiceClient.validateToken(sessionId, token)
                .flatMap(isValid -> {
                    if (Boolean.TRUE.equals(isValid)) {
                        ServerHttpRequest mutatedRequest = exchange.getRequest()
                                .mutate()
                                .header("X-Session-Id", String.valueOf(sessionId))
                                .build();
                        return chain.filter(exchange.mutate().request(mutatedRequest).build());
                    } else {
                        ServerHttpResponse response = exchange.getResponse();
                        response.setStatusCode(HttpStatus.UNAUTHORIZED);
                        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

                        Map<String, Object> bodyMap = Map.of(
                                "status", HttpStatus.UNAUTHORIZED.value(),
                                "error", ErrorCode.INVALID_ACCESS_TOKEN.name(),
                                "message", "Invalid access token",
                                "timestamp", LocalDateTime.now().toString()
                        );

                        try {
                            ObjectMapper mapper = new ObjectMapper();
                            byte[] bytes = mapper.writeValueAsBytes(bodyMap);
                            DataBuffer buffer = response.bufferFactory().wrap(bytes);
                            return response.writeWith(Mono.just(buffer));
                        } catch (Exception er) {
                            response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
                            return response.setComplete();
                        }
                    }
                });
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
