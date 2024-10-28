package com.example.springsecurityjwt;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/private")
public class PrivateController {

    @GetMapping // proteger o acesso a essa rota
    public String getMessage() {
        return "Hello from private API controller"; // proteger o acesso a essa rota
    }
}
