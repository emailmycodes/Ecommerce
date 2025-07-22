package com.wings1.ecommerce.dto;

import com.wings1.ecommerce.models.*;
import com.wings1.ecommerce.repository.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataLoader implements CommandLineRunner {

    @Autowired
    private UserInfoRepository userRepo;

    @Autowired
    private CategoryRepo categoryRepo;

    @Autowired
    private CartRepo cartRepo;

    @Autowired
    private ProductRepo productRepo;

    @Autowired
    private CartProductRepo cartProductRepo;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception{
    loadUserData();loadData();
    }

    private  void loadUserData(){
        userRepo.save(new UserInfo("jack",passwordEncoder.encode("pass_word"),"CONSUMER"));
        userRepo.save(new UserInfo("bob",passwordEncoder.encode("pass_word"),"CONSUMER"));
        userRepo.save(new UserInfo("apple",passwordEncoder.encode("pass_word"),"SELLER"));
        userRepo.save(new UserInfo("glaxo",passwordEncoder.encode("pass_word"),"SELLER"));
        System.out.println("user data added");
    }

    private void loadData(){
        Category category1= new Category("Fashion");
        Category category2= new Category("Electronics");
        Category category3= new Category("Books");
        Category category4= new Category("Groceries");
        Category category5= new Category("Medicines");

        categoryRepo.save(category1);
        categoryRepo.save(category2);
        categoryRepo.save(category3);
        categoryRepo.save(category4);
        categoryRepo.save(category5);

        System.out.println("Category data added");

        // Fetch UserInfo for users(jack and bob)using userId
        UserInfo user3 = userRepo.findById(3).orElseThrow(()-> new RuntimeException("User not found"));
        UserInfo user4 = userRepo.findById(4).orElseThrow(()-> new RuntimeException("User not found"));

        Category cate1= categoryRepo.findById(2).orElseThrow(()-> new RuntimeException("Category not found"));
        Category cate2= categoryRepo.findById(5).orElseThrow(()-> new RuntimeException("Category not found"));
        Category cate3= categoryRepo.findById(3).orElseThrow(()-> new RuntimeException("Category not found"));


        Product product1= new Product("Apple iPad 10.2 8th Gen WiFi iOS Tablet",29190,user3,cate1);
        Product product2= new Product("Crocin pain relief tablet",10,user4,cate2);
        Product product3= new Product("Harry Potter noval",10,user3,cate3);

        productRepo.save(product1);
        productRepo.save(product2);
        productRepo.save(product3);

        System.out.println("product data added");

        UserInfo user1= userRepo.findById(1).orElseThrow(()-> new RuntimeException("User not found"));
        UserInfo user2= userRepo.findById(2).orElseThrow(()-> new RuntimeException("User not found"));

        Cart cart1=new Cart(20.0,user1);
        Cart cart2=new Cart(0.0,user2);

        cartRepo.save(cart1);
        cartRepo.save(cart2);

        System.out.println("Cart data added");

        Product savedProuct1= productRepo.findById(product1.getProductId()).orElseThrow(()-> new RuntimeException("Product not found"));
        Product savedProuct2= productRepo.findById(product2.getProductId()).orElseThrow(()-> new RuntimeException("Product not found"));

        CartProduct cartProduct1 = new CartProduct(cart1,savedProuct2,2);
        cartProductRepo.save(cartProduct1);

        System.out.println("Cartproduct added");

    }



}
