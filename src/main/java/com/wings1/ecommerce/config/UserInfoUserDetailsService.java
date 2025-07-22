package com.wings1.ecommerce.config;

import com.wings1.ecommerce.models.UserInfo;
import com.wings1.ecommerce.repository.UserInfoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserInfoUserDetailsService implements UserDetailsService {

    @Autowired
    private UserInfoRepository userInfoRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserInfo userInfo = userInfoRepository.findByUsername(username) // Changed to `findByUsername`
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        return new UserInfoUserDetails(userInfo);
    }
}