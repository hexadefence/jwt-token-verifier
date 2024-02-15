package com.hexadefence.api.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/secure-api")
public class SecureController {

    @RequestMapping
    public Map sayHello(){

        return Map.of("message", "Hello");
    }
}
