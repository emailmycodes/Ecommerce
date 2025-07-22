package com.wings1.ecommerce.controller;

import com.wings1.ecommerce.models.Category;
import com.wings1.ecommerce.models.Product;
import com.wings1.ecommerce.models.UserInfo;
import com.wings1.ecommerce.repository.CategoryRepo;
import com.wings1.ecommerce.repository.ProductRepo;
import com.wings1.ecommerce.repository.UserInfoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.security.Principal;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth/seller")
public class SellerController {

    @Autowired
    private ProductRepo productRepo;

    @Autowired
    private UserInfoRepository userRepo;

    @Autowired
    private CategoryRepo categoryRepo;
    @PostMapping("/seller/product")
    public ResponseEntity<Object> postProduct(Principal principal, @RequestBody Product product) {
        // Set the seller from the logged-in user
        String username = principal.getName();
        Optional<UserInfo> sellerOpt = userRepo.findByUsername(username);

        if (sellerOpt.isPresent()) {
            UserInfo seller = sellerOpt.get();
            product.setSeller(seller);

            // Save the product directly without checking if category exists
            productRepo.save(product);

            URI location = URI.create("/api/auth/seller/product/" + product.getProductId());
            return ResponseEntity.created(location).build();
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Seller not found");
        }
    }


    @GetMapping("/product")
    public ResponseEntity<Object> getAllProducts(Principal principal) {
        String username = principal.getName();
        UserInfo seller = userRepo.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));
        List<Product> products = productRepo.findBySellerUserId(seller.getUserId());
        return ResponseEntity.ok(products);
    }

    @GetMapping("/product/{productId}")
    public ResponseEntity<Object> getProduct(Principal principal, @PathVariable Integer productId) {
        String username = principal.getName();
        UserInfo seller = userRepo.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));
        Product product = productRepo.findBySellerUserIdAndProductId(seller.getUserId(), productId)
                .orElseThrow(() -> new RuntimeException("Product not found or does not belong to the seller"));
        return ResponseEntity.ok(product);
    }

    @PutMapping("/product")
    public ResponseEntity<Object> putProduct(Principal principal, @RequestBody Product updatedProduct) {
        String username = principal.getName();
        UserInfo seller = userRepo.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));
        Product existingProduct = productRepo.findBySellerUserIdAndProductId(seller.getUserId(), updatedProduct.getProductId())
                .orElseThrow(() -> new RuntimeException("Product not found or unauthorized"));
        updatedProduct.setSeller(seller);
        Product saved = productRepo.save(updatedProduct);
        return ResponseEntity.ok(saved);
    }

    @DeleteMapping("/product/{productId}")
    public ResponseEntity<Product> deleteProduct(Principal principal, @PathVariable Integer productId) {
        String username = principal.getName();
        UserInfo seller = userRepo.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));
        Product product = productRepo.findBySellerUserIdAndProductId(seller.getUserId(), productId)
                .orElseThrow(() -> new RuntimeException("Product not found or unauthorized"));
        productRepo.delete(product);
        return ResponseEntity.ok(product);
    }
}
