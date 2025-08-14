package com.cognito.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private static final String REGION = "ap-south-1"; // your region
    private static final String USER_POOL_ID = "ap-south-1_XXXXXXX"; // your user pool id
    private static final String JWKS_URL = "https://cognito-idp." + REGION + ".amazonaws.com/" + USER_POOL_ID + "/.well-known/jwks.json";

    private final Map<String, PublicKey> publicKeys = new ConcurrentHashMap<>();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            try {
                Claims claims = validateToken(token);
                request.setAttribute("claims", claims);
                request.setAttribute("email", claims.get("email"));
                request.setAttribute("sub", claims.getSubject());
            } catch (Exception e) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Invalid token: " + e.getMessage());
                logger.info("Invalid token");
                return;
            }
        } else {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Missing Authorization header");
            logger.info("Missing Authorization header");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private Claims validateToken(String token) throws Exception {
        String kid = getKeyIdFromToken(token);
        PublicKey publicKey = publicKeys.computeIfAbsent(kid, k -> fetchPublicKey(kid));
        logger.info("Using public key for " + kid + " : " + publicKey);

        return Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private String getKeyIdFromToken(String token) throws IOException {
        String[] split = token.split("\\.");
        String headerJson = new String(Base64.getUrlDecoder().decode(split[0]));
        ObjectMapper mapper = new ObjectMapper();
        JsonNode header = mapper.readTree(headerJson);
        return header.get("kid").asText();
    }

    private PublicKey fetchPublicKey(String kid) {
        try {
            URL url = new URL(JWKS_URL);
            ObjectMapper mapper = new ObjectMapper();
            JsonNode keysNode = mapper.readTree(url).get("keys");

            for (JsonNode keyNode : keysNode) {
                if (keyNode.get("kid").asText().equals(kid)) {
                    BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(keyNode.get("n").asText()));
                    BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(keyNode.get("e").asText()));

                    RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
                    KeyFactory kf = KeyFactory.getInstance("RSA");
                    return kf.generatePublic(spec);
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to fetch public key", e);
        }
        throw new RuntimeException("Public key not found for kid: " + kid);
    }
}
