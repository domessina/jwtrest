package be.technocite.jwtrest.api.controller;

import be.technocite.jwtrest.api.dto.CreateProductCommand;
import be.technocite.jwtrest.api.dto.ProductDto;
import be.technocite.jwtrest.service.ProductService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class ProductController {

    @Autowired
    private ProductService productService;

    @GetMapping("/api/products")
    public List<ProductDto> findAll() {
        return productService.findAll();
    }

    @PostMapping("/api/products")
    public String create(@RequestBody CreateProductCommand command) {
        return productService.handleCreateCommand(command);
    }

    @GetMapping("/api/products/{id}")
    public ProductDto getProduct(@PathVariable String id) {
        return productService.findById(id);
    }
}

