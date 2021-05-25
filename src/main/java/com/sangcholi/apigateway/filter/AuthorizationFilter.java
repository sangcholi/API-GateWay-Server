package com.sangcholi.apigateway.filter;

import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.context.environment.EnvironmentManager;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class AuthorizationFilter extends AbstractGatewayFilterFactory<AuthorizationFilter.Config> {
    private Environment env;

    @Autowired
    public AuthorizationFilter(Environment env) {
        super(Config.class);
        this.env = env;
    }

    @Override
    public GatewayFilter apply(Config config) {
        GatewayFilter gatewayFilter = (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "no authorization header", HttpStatus.NON_AUTHORITATIVE_INFORMATION);
            }

            String authToken = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            String jwt = authToken.replace("Bearer", "");

            if (!isValidJwt(jwt)) {
                return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
            }
            return chain.filter(exchange);
        };
        return gatewayFilter;
    }

    private boolean isValidJwt(String jwt) {
        try {
            String subject = Jwts.parser().setSigningKey(env.getProperty("token.secret"))
                    .parseClaimsJws(jwt).getBody()
                    .getSubject();

            if (subject == null || subject.isBlank()) {
                return false;
            }
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    private Mono<Void> onError(ServerWebExchange exchange, String error, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        log.error(error);

        return response.setComplete();
    }


    static class Config {
    }

}
