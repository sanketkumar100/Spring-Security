package com.example.securitydemo;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Greetings
{
    @GetMapping("/hello")
    public String sayHello()
    {
        return "Hello from sanket's app";
    }
    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String userEndpoint()
    {
        return "Hello from sanket's user";
    }
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String adminEndpoint()
    {
        return "Hello from sanket's Admin";
    }
}
