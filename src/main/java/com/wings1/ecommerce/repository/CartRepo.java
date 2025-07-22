package com.wings1.ecommerce.repository;

import com.wings1.ecommerce.models.Cart;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CartRepo extends JpaRepository<Cart,Integer> {
    Optional<Cart> findByUserUsername(String username);
}
