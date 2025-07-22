package com.wings1.ecommerce.repository;

import com.wings1.ecommerce.models.UserInfo;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserInfoRepository extends JpaRepository<UserInfo, Integer> {
    Optional<UserInfo> findByUsername(String username);

    boolean existsByUsername(String username);
}
