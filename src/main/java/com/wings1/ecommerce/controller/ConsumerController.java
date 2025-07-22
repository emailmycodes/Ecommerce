package com.wings1.ecommerce.controller;

import com.wings1.ecommerce.models.Cart;
import com.wings1.ecommerce.models.CartProduct;
import com.wings1.ecommerce.models.Product;
import com.wings1.ecommerce.repository.CartProductRepo;
import com.wings1.ecommerce.repository.CartRepo;
import com.wings1.ecommerce.repository.ProductRepo;
import com.wings1.ecommerce.repository.UserInfoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth/consumer")
public class ConsumerController {

    @Autowired
    private ProductRepo productRepo;

    @Autowired
    private CartProductRepo cartProductRepo;

    @Autowired
    private UserInfoRepository userRepo;

    @Autowired
    private CartRepo cartRepo;

    @GetMapping("/cart")
    public ResponseEntity<Object> getCart(Principal principal) {
        String username = principal.getName();
        Optional<Cart> cartItems = cartRepo.findByUserUsername(username);
        return ResponseEntity.ok(cartItems);
    }

    @PostMapping("/cart")
    public ResponseEntity<Object> postCart(Principal principal, @RequestBody Product product) {
        String username = principal.getName();

        var user = userRepo.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Cart cart = cartRepo.findByUserUsername(username).orElseGet(() -> {
            Cart newCart = new Cart(0.0, user);
            return cartRepo.save(newCart);
        });

        boolean exists = cart.getCartProducts().stream()
                .anyMatch(cp -> cp.getProduct().getProductId() == product.getProductId());

        if (exists) {
            return ResponseEntity.status(409).body("Product already exists in cart");
        }

        Product dbProduct = productRepo.findById(product.getProductId())
                .orElseThrow(() -> new RuntimeException("Product not found"));

        CartProduct cartProduct = new CartProduct(cart, dbProduct, 1);
        cartProductRepo.save(cartProduct);

        cart.updateTotalAmount(dbProduct.getPrice());
        cartRepo.save(cart);

        return ResponseEntity.status(201).body("Product added to cart");
    }


    @PutMapping("/cart")
    public ResponseEntity<Object> putCart(Principal principal, @RequestBody CartProduct cp) {
        return null;
    }

    @DeleteMapping("/cart")
    public ResponseEntity<Object> deleteCart(Principal principal, @RequestBody Product product) {
        return null;
    }
}
