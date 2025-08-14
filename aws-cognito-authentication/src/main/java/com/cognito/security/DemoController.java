package com.cognito.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class DemoController {

    @GetMapping("/me")
    public ResponseEntity<String> getUserInfo(HttpServletRequest request) {
        String email = (String) request.getAttribute("email");
        String sub = (String) request.getAttribute("sub");

        return ResponseEntity.ok("User: " + email + " | ID: " + sub);
    }
}

