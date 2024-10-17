package com.nusiss.apigateway.filter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nusiss.apigateway.exception.CustomException;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.*;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;


@Component
public class TokenAuthenticationFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();
        String uri = request.getPath().toString();
        String method = exchange.getRequest().getMethod().toString();
        //all requests need to validate except for /validateUserAndPassword and /login
        if(!uri.contains("/validateUserAndPassword")
                && !uri.contains("/login")
                && !uri.contains("/validateToken")
                && !uri.contains("swagger")){
            String token = request.getHeaders().getFirst("authToken");

            try {
                if(!validateToken(token)){
                    throw new CustomException("Invalid token.");
                }
            } catch (Exception e) {
                //throw new RuntimeException(e);
                return handleException(response, e);
            }
            // Check if the user has permission to access the requested API
            boolean hasPermission = false;
            try {
                //hasPermission = permission(token, uri, method);
                //set to true for testing
                hasPermission = true;
                //if has no permission
                if (!hasPermission) {
                    exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                    throw new CustomException("No permission for the url: "+uri);
                }
            } catch (Exception e) {
                return handleException(response, e);
            }
        }

        // If token is valid, proceed to the next filter in the chain
        return chain.filter(exchange);
    }

    private boolean permission(String token, String url, String method) throws Exception {
        RestTemplate restTemplate = new RestTemplate();
        StringBuffer fullurl = new StringBuffer("http://localhost:8084/permission?url=");
        fullurl.append(url).append("&method=").append(method);

        // Create headers
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.add("authToken", token);

        // Create the request body
        /*Map<String, String> requestBody = new HashMap<>();
        requestBody.put("authToken", token);*/

        // Create the HttpEntity object containing headers and the body
        HttpEntity<Map<String, String>> requestEntity = new HttpEntity<>(headers);

        // Send the POST request
        ResponseEntity<Boolean> response = restTemplate.exchange(
                fullurl.toString(),
                HttpMethod.GET,
                requestEntity,
                new ParameterizedTypeReference<Boolean>() {}
        );
        Boolean isValidated = response.getBody();

        return isValidated;
    }

    private Mono<Void>  handleException(ServerHttpResponse response, Exception ex) {
        // Prepare response structure
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("success", false);
        errorResponse.put("message", ex.getMessage());
        errorResponse.put("data", null);

        response.setStatusCode(org.springframework.http.HttpStatus.UNAUTHORIZED);

        // Set headers for JSON response
        response.getHeaders().set(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        ObjectMapper objectMapper = new ObjectMapper();
        DataBuffer buffer = null;
        try {
            buffer = response.bufferFactory().wrap(objectMapper.writeValueAsString(errorResponse).getBytes(StandardCharsets.UTF_8));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }

        // Write the JSON response and complete
        return response.writeWith(Mono.just(buffer));

    }

    private boolean validateToken(String token) throws Exception {
        RestTemplate restTemplate = new RestTemplate();
        String url = "http://localhost:8084/validateToken";

        // Create headers
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        // Create the request body
        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("token", token);

        // Create the HttpEntity object containing headers and the body
        HttpEntity<Map<String, String>> requestEntity = new HttpEntity<>(requestBody, headers);

        // Send the POST request
        ResponseEntity<Boolean> response = restTemplate.exchange(
                url,
                HttpMethod.POST,
                requestEntity,
                new ParameterizedTypeReference<Boolean>() {}
        );
        Boolean isValidated = response.getBody();

        return isValidated;
    }


    @Override
    public int getOrder() {
        return -1;  // Set filter order; lower value means higher precedence
    }
}
