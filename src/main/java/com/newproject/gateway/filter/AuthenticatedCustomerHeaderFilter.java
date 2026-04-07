package com.newproject.gateway.filter;

import com.newproject.gateway.service.CustomerIdentityResolver;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AuthenticatedCustomerHeaderFilter implements GlobalFilter, Ordered {
    public static final String CUSTOMER_ID_HEADER = "X-Authenticated-Customer-Id";
    public static final String SUBJECT_HEADER = "X-Authenticated-Subject";

    private final CustomerIdentityResolver customerIdentityResolver;

    public AuthenticatedCustomerHeaderFilter(CustomerIdentityResolver customerIdentityResolver) {
        this.customerIdentityResolver = customerIdentityResolver;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return exchange.getPrincipal()
            .cast(Authentication.class)
            .flatMap(authentication -> applyAuthenticatedContext(exchange, chain, authentication))
            .switchIfEmpty(chain.filter(stripHeaders(exchange)));
    }

    private Mono<Void> applyAuthenticatedContext(ServerWebExchange exchange, GatewayFilterChain chain, Authentication authentication) {
        if (!(authentication instanceof JwtAuthenticationToken jwtAuthentication) || !authentication.isAuthenticated()) {
            return chain.filter(stripHeaders(exchange));
        }

        ServerHttpRequest.Builder builder = strippedRequestBuilder(exchange);
        Jwt jwt = jwtAuthentication.getToken();
        if (StringUtils.hasText(jwt.getSubject())) {
            builder.header(SUBJECT_HEADER, jwt.getSubject());
        }

        if (isAdmin(jwtAuthentication)) {
            return chain.filter(exchange.mutate().request(builder.build()).build());
        }

        return customerIdentityResolver.resolveCustomerId(jwt)
            .defaultIfEmpty("")
            .flatMap(customerId -> {
                if (StringUtils.hasText(customerId)) {
                    builder.header(CUSTOMER_ID_HEADER, customerId);
                }
                return chain.filter(exchange.mutate().request(builder.build()).build());
            });
    }

    private ServerWebExchange stripHeaders(ServerWebExchange exchange) {
        return exchange.mutate().request(strippedRequestBuilder(exchange).build()).build();
    }

    private ServerHttpRequest.Builder strippedRequestBuilder(ServerWebExchange exchange) {
        ServerHttpRequest.Builder builder = exchange.getRequest().mutate();
        builder.headers(headers -> {
            headers.remove(CUSTOMER_ID_HEADER);
            headers.remove(SUBJECT_HEADER);
        });
        return builder;
    }

    private boolean isAdmin(JwtAuthenticationToken authentication) {
        return authentication.getAuthorities().stream()
            .anyMatch(authority -> "ROLE_ADMIN".equalsIgnoreCase(authority.getAuthority()));
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 20;
    }
}
