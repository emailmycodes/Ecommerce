package com.wings1.ecommerce.repository;

import com.wings1.ecommerce.models.CartProduct;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CartProductRepo extends JpaRepository<CartProduct, Integer> {

    Optional<CartProduct> findByCartUserUserIdAndProductProductId(Integer userId, Integer productId);

    @Modifying
    @Transactional
    void deleteByCartUserUserIdAndProductProductId(Integer userId, Integer productId);

    List<CartProduct> findByCartUserUserId(Integer userId);
}
