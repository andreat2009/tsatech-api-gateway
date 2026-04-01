package com.newproject.gateway.error;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.ErrorResponse;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebExceptionHandler;
import reactor.core.publisher.Mono;

@Component
@Order(-2)
public class GlobalGatewayExceptionHandler implements WebExceptionHandler {
    private static final Logger logger = LoggerFactory.getLogger(GlobalGatewayExceptionHandler.class);

    private final ObjectMapper objectMapper;

    public GlobalGatewayExceptionHandler(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable throwable) {
        if (exchange.getResponse().isCommitted()) {
            return Mono.error(throwable);
        }

        HttpStatus status = resolveStatus(throwable);
        String reference = UUID.randomUUID().toString();
        String path = exchange.getRequest().getPath().value();
        String message = resolveMessage(throwable, status);

        if (status.is5xxServerError()) {
            logger.error("Unhandled gateway error [{}] on {}", reference, path, throwable);
        } else {
            logger.warn("Gateway request error [{}] on {}: {}", reference, path, throwable.getMessage());
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", OffsetDateTime.now());
        body.put("status", status.value());
        body.put("error", status.getReasonPhrase());
        body.put("message", message);
        body.put("path", path);
        body.put("reference", reference);

        byte[] payload;
        try {
            payload = objectMapper.writeValueAsBytes(body);
        } catch (Exception serializationException) {
            payload = ("{\"status\":" + status.value() + ",\"error\":\"" + status.getReasonPhrase() + "\",\"message\":\"" + message.replace("\"", "'") + "\",\"reference\":\"" + reference + "\"}")
                .getBytes(StandardCharsets.UTF_8);
        }

        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(payload)));
    }

    private HttpStatus resolveStatus(Throwable throwable) {
        String simpleName = throwable.getClass().getSimpleName();
        if ("BadRequestException".equals(simpleName)) {
            return HttpStatus.BAD_REQUEST;
        }
        if ("NotFoundException".equals(simpleName)) {
            return HttpStatus.NOT_FOUND;
        }
        if ("AccessDeniedException".equals(simpleName)) {
            return HttpStatus.FORBIDDEN;
        }
        if (throwable instanceof ErrorResponse errorResponse) {
            HttpStatus status = HttpStatus.resolve(errorResponse.getBody().getStatus());
            if (status != null) {
                return status;
            }
        }
        return HttpStatus.INTERNAL_SERVER_ERROR;
    }

    private String resolveMessage(Throwable throwable, HttpStatus status) {
        if (status == HttpStatus.INTERNAL_SERVER_ERROR) {
            return "Unexpected gateway error. Please retry later.";
        }
        if (throwable.getMessage() != null && !throwable.getMessage().isBlank()) {
            return throwable.getMessage();
        }
        return status.getReasonPhrase();
    }
}
