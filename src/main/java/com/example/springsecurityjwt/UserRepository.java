package com.example.springsecurityjwt;

import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

// vai trabalhar com entidade User e o tipo de chave primária é String
public interface UserRepository extends CrudRepository<User, String>
{
    Optional<User> findByUsername(String username);

}
