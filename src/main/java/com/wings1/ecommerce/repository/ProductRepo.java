package com.wings1.ecommerce.repository;

import com.wings1.ecommerce.models.Product;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ProductRepo extends JpaRepository<Product, Integer> {
    List<Product> findByProductNameContainingIgnoreCaseOrCategory_CategoryNameContainingIgnoreCase(String productName, String categoryName);

    List<Product> findBySellerUserId(Integer sellerId);

    Optional<Product> findBySellerUserIdAndProductId(Integer sellerId, Integer productId);
}
