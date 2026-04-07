package com.newproject.gateway.service;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Service
public class CustomerIdentityResolver {
    private final WebClient webClient;
    private final String customerServiceUrl;

    public CustomerIdentityResolver(
        WebClient.Builder webClientBuilder,
        @Value("${CUSTOMER_SERVICE_URL:http://customer-service.${APP_NAMESPACE:ecommerce}.svc.cluster.local:8443}") String customerServiceUrl
    ) {
        this.webClient = webClientBuilder.build();
        this.customerServiceUrl = normalizeBaseUrl(customerServiceUrl);
    }

    public Mono<String> resolveCustomerId(Jwt jwt) {
        if (jwt == null || !StringUtils.hasText(jwt.getSubject()) || !StringUtils.hasText(customerServiceUrl)) {
            return Mono.empty();
        }

        return webClient.get()
            .uri(customerServiceUrl + "/api/customers?keycloakUserId={subject}", jwt.getSubject())
            .headers(headers -> headers.setBearerAuth(jwt.getTokenValue()))
            .retrieve()
            .bodyToFlux(CustomerLookupResponse.class)
            .next()
            .map(CustomerLookupResponse::getId)
            .map(String::valueOf)
            .filter(StringUtils::hasText)
            .onErrorResume(ex -> Mono.empty());
    }

    private String normalizeBaseUrl(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.endsWith("/") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class CustomerLookupResponse {
        private Long id;

        public Long getId() {
            return id;
        }

        public void setId(Long id) {
            this.id = id;
        }
    }
}
