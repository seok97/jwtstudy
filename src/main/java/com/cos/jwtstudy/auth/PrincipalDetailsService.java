package com.cos.jwtstudy.auth;

import com.cos.jwtstudy.model.User;
import com.cos.jwtstudy.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("################# PrincipalDetailsService 의 loaduserbyusername 실행");
        User userEntity = userRepository.findByUsername(username);
        System.out.println("userEntity: " + userEntity);
        return new PrincipalDetails(userEntity);
    }
}
