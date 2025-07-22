package com.wings1.ecommerce.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;

import java.util.List;

@Entity
public class Cart {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int cartId;

    private double totalAmount;

    @OneToOne(fetch = FetchType.EAGER, cascade = CascadeType.REMOVE)
    @JoinColumn(name = "user_id", referencedColumnName = "userId")
    @JsonIgnore
    private UserInfo user;

    @OneToMany(fetch = FetchType.EAGER, mappedBy = "cart")
    private List<CartProduct> cartProducts;

    // No-argument constructor
    public Cart() {
    }

    public Cart(Integer cartId,Double totalAmount,UserInfo user,List<CartProduct> cartProducts) {
        this.cartId=cartId;
        this.totalAmount=totalAmount;
        this.user=user;
        this.cartProducts=cartProducts;
    }

    // Constructor with totalAmount and user
    public Cart(Double totalAmount, UserInfo user) {
        this.totalAmount = totalAmount;
        this.user = user;
    }

    public int getCartId() {
        return cartId;
    }

    public void setCartId(int cartId) {
        this.cartId = cartId;
    }

    public double getTotalAmount() {
        return totalAmount;
    }

    public void setTotalAmount(double totalAmount) {
        this.totalAmount = totalAmount;
    }

    public UserInfo getUser() {
        return user;
    }

    public void setUser(UserInfo user) {
        this.user = user;
    }

    public List<CartProduct> getCartProducts() {
        return cartProducts;
    }

    public void setCartProducts(List<CartProduct> cartProducts) {
        this.cartProducts = cartProducts;
    }

    public void updateTotalAmount(Double price) {
        this.totalAmount += price;
    }
}
