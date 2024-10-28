# Visão Geral do Projeto

## Introdução
Este projeto é uma aplicação Spring Boot que implementa autenticação e autorização baseadas em JWT. Utiliza Maven para gerenciamento de dependências e inclui configurações para segurança, codificação/decodificação JWT e autenticação de usuários.

## Tecnologias Utilizadas
- **Java**: Linguagem de programação principal.
- **Spring Boot**: Framework para construção da aplicação.
- **Spring Security**: Para segurança da aplicação.
- **JWT (JSON Web Tokens)**: Para autenticação e autorização.
- **Maven**: Para gerenciamento de dependências.
- **SQL**: Para operações de banco de dados.

## Estrutura do Projeto
O projeto está organizado em vários pacotes e arquivos:

- **src/main/java/com/example/springsecurityjwt**
  - `AuthenticationController.java`: Lida com requisições de autenticação.
  - `JwtService.java`: Gera tokens JWT.
  - `SecurityConfig.java`: Configura as definições de segurança, incluindo codificação/decodificação JWT.

- **src/main/resources/templates**
  - `data.sql`: Contém scripts SQL para inicialização do banco de dados.
  - `app.pub`: Atualmente vazio, pode ser usado para armazenar a chave pública para verificação JWT.

## Componentes Principais

### AuthenticationController
Lida com o endpoint `/authenticate` para autenticar usuários.

```java
package com.example.springsecurityjwt;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthenticationController {
    private final AuthenticationService authenticationService;

    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("authenticate")
    public String authenticate(Authentication authentication) {
        return authenticationService.authenticate(authentication);
    }
}
```

### JwtService
Gera tokens JWT para usuários autenticados.

```java
package com.example.springsecurityjwt;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.stream.Collectors;

@Service
public class JwtService {
    private final JwtEncoder encoder;

    public JwtService(JwtEncoder encoder) {
        this.encoder = encoder;
    }

    public String generateToken(Authentication authentication) {
        Instant now = Instant.now();
        long exp = now.getEpochSecond() + 3600; // token expira em 1 hora

        String scope = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));

        // Retorna o token gerado (este é um placeholder, substitua pela lógica real de geração de token)
        return "generated-token";
    }
}
```

### SecurityConfig
Configura as definições de segurança, incluindo codificação/decodificação JWT e codificação de senhas.

```java
package com.example.springsecurityjwt;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${public-key}")
    private RSAPublicKey key;
    @Value("${private-key}")
    private RSAPrivateKey privateKey;

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth.requestMatchers("/authenticate").permitAll()
                    .anyRequest().authenticated())
            .httpBasic(Customizer.withDefaults())
            .oauth2ResourceServer(conf -> conf.jwt(Customizer.withDefaults()));
        return http.build();
    }

    @Bean
    JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(key).build();
    }

    @Bean
    JwtEncoder jwtEncoder() {
        var jwk = new RSAKey.Builder(key).privateKey(privateKey).build();
        var jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwks);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

## Script de Inicialização SQL
O arquivo `data.sql` contém scripts SQL para inicialização do banco de dados.

```sql
INSERT INTO USERS (username, password) VALUES ('', '');
```

## Conclusão
Este projeto demonstra uma configuração básica para uma aplicação Spring Boot com autenticação e autorização baseadas em JWT. Inclui configurações para segurança, codificação/decodificação JWT e autenticação de usuários, tornando-se uma base sólida para construir aplicações seguras.
