package com.example.springsecurityjwt;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class UserDatailsServiceImpl  implements UserDetailsService {
    private final UserRepository userRepository;

    public UserDatailsServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username)  throws UsernameNotFoundException {
        return userRepository.findByUsername(username)  // usado para buscar um usuário no banco de dados
                .map(UserAuthenticated::new) // vai ser mapeado para um UserAuthenticated
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

    }
}
