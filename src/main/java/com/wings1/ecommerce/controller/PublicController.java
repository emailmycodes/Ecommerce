package com.wings1.ecommerce.controller;

import com.wings1.ecommerce.models.Product;
import com.wings1.ecommerce.repository.ProductRepo;
import com.wings1.ecommerce.repository.UserInfoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/public")
public class PublicController {

    @Autowired
    private UserInfoRepository userInfoRepository;

    @Autowired
    private ProductRepo productRepo;

    // Search products by keyword (matches product name or category name)
    @GetMapping("/product/search")
    public ResponseEntity<List<Product>> searchProducts(@RequestParam(required = false) String keyword) {
        if (keyword == null || keyword.trim().isEmpty()) {
            return ResponseEntity.badRequest().build(); // You could also return an empty list
        }

        List<Product> products = productRepo
                .findByProductNameContainingIgnoreCaseOrCategory_CategoryNameContainingIgnoreCase(keyword, keyword);

        return ResponseEntity.ok(products);
    }
}
