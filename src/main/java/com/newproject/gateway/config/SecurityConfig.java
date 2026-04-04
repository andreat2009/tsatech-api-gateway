package com.newproject.gateway.config;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .authorizeExchange(exchange -> exchange
                .pathMatchers(HttpMethod.GET, "/actuator/health", "/actuator/info").permitAll()

                // catalog/reviews
                .pathMatchers(HttpMethod.GET, "/api/catalog/reviews/**").hasRole("ADMIN")
                .pathMatchers(HttpMethod.POST, "/api/catalog/products/*/reviews").authenticated()
                .pathMatchers(HttpMethod.GET, "/api/catalog/**").permitAll()
                .pathMatchers("/api/catalog/**").hasRole("ADMIN")

                // CMS / BLOG / CONTACT public endpoints
                .pathMatchers(HttpMethod.GET, "/api/cms/information/**").permitAll()
                .pathMatchers(HttpMethod.GET, "/api/cms/settings/public").permitAll()
                .pathMatchers(HttpMethod.GET, "/api/cms/blog/posts/**").permitAll()
                .pathMatchers(HttpMethod.POST, "/api/cms/blog/posts/*/comments").permitAll()
                .pathMatchers(HttpMethod.POST, "/api/cms/contact").permitAll()
                .pathMatchers(HttpMethod.POST, "/api/cms/analytics/events").permitAll()

                // CMS / BLOG / CONTACT admin endpoints
                .pathMatchers(HttpMethod.POST, "/api/cms/information", "/api/cms/information/**").hasRole("ADMIN")
                .pathMatchers(HttpMethod.PUT, "/api/cms/information/**").hasRole("ADMIN")
                .pathMatchers(HttpMethod.DELETE, "/api/cms/information/**").hasRole("ADMIN")
                .pathMatchers(HttpMethod.GET, "/api/cms/settings", "/api/cms/settings/**").hasRole("ADMIN")
                .pathMatchers(HttpMethod.PUT, "/api/cms/settings", "/api/cms/settings/**").hasRole("ADMIN")
                .pathMatchers(HttpMethod.POST, "/api/cms/blog/posts", "/api/cms/blog/posts/**").hasRole("ADMIN")
                .pathMatchers(HttpMethod.PUT, "/api/cms/blog/posts/**").hasRole("ADMIN")
                .pathMatchers(HttpMethod.DELETE, "/api/cms/blog/posts/**").hasRole("ADMIN")
                .pathMatchers(HttpMethod.GET, "/api/cms/blog/comments", "/api/cms/blog/comments/**").hasRole("ADMIN")
                .pathMatchers(HttpMethod.PATCH, "/api/cms/blog/comments/**").hasRole("ADMIN")
                .pathMatchers(HttpMethod.GET, "/api/cms/contact", "/api/cms/contact/**").hasRole("ADMIN")
                .pathMatchers(HttpMethod.PATCH, "/api/cms/contact/**").hasRole("ADMIN")
                .pathMatchers(HttpMethod.GET, "/api/cms/analytics", "/api/cms/analytics/**").hasRole("ADMIN")

                // guest checkout public flow
                .pathMatchers(HttpMethod.POST, "/api/customers").permitAll()
                .pathMatchers(HttpMethod.POST, "/api/customers/*/addresses").permitAll()
                .pathMatchers(HttpMethod.GET, "/api/customers/custom-fields", "/api/customers/custom-fields/**").permitAll()
                .pathMatchers(HttpMethod.POST, "/api/pricing/quote").permitAll()
                .pathMatchers(HttpMethod.POST, "/api/orders").permitAll()
                .pathMatchers(HttpMethod.POST, "/api/orders/*/items").permitAll()
                .pathMatchers(HttpMethod.PUT, "/api/orders/*").permitAll()
                .pathMatchers(HttpMethod.GET, "/api/payments/methods").permitAll()
                .pathMatchers(HttpMethod.POST, "/api/payments").permitAll()
                .pathMatchers(HttpMethod.POST, "/api/payments/*/capture/paypal", "/api/payments/*/complete/fabrick").permitAll()
                .pathMatchers(HttpMethod.POST, "/api/payments/webhooks/paypal", "/api/payments/webhooks/fabrick").permitAll()
                .pathMatchers(HttpMethod.POST, "/api/shipments").permitAll()

                .pathMatchers(HttpMethod.POST, "/api/notifications/order-confirmation").permitAll()
                .pathMatchers(HttpMethod.GET, "/api/notifications/ping").permitAll()

                // customer extras (dedicated microservices)
                .pathMatchers("/api/customers/*/newsletter", "/api/customers/*/newsletter/**").authenticated()
                .pathMatchers("/api/customers/*/rewards", "/api/customers/*/rewards/**").authenticated()
                .pathMatchers("/api/customers/*/transactions", "/api/customers/*/transactions/**").authenticated()
                .pathMatchers("/api/customers/*/subscriptions", "/api/customers/*/subscriptions/**").authenticated()
                .pathMatchers("/api/customers/*/downloads", "/api/customers/*/downloads/**").authenticated()

                .pathMatchers("/api/**").authenticated()
                .anyExchange().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
            )
            .build();
    }

    private ReactiveJwtAuthenticationConverterAdapter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(this::extractAuthorities);
        return new ReactiveJwtAuthenticationConverterAdapter(converter);
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        Collection<GrantedAuthority> authorities = new ArrayList<>();

        Map<String, Object> realmAccess = jwt.getClaim("realm_access");
        if (realmAccess != null && realmAccess.get("roles") instanceof List<?> roles) {
            for (Object role : roles) {
                authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
                authorities.add(new SimpleGrantedAuthority("ROLE_" + role.toString().toUpperCase(java.util.Locale.ROOT)));
            }
        }

        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        if (resourceAccess != null) {
            resourceAccess.forEach((client, access) -> {
                if (access instanceof Map<?, ?> accessMap) {
                    Object rolesObj = accessMap.get("roles");
                    if (rolesObj instanceof List<?> roles) {
                        for (Object role : roles) {
                            authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
                            authorities.add(new SimpleGrantedAuthority("ROLE_" + role.toString().toUpperCase(java.util.Locale.ROOT)));
                        }
                    }
                }
            });
        }

        return authorities;
    }
}
