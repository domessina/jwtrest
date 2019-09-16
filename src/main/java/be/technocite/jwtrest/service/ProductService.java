package be.technocite.jwtrest.service;

import be.technocite.jwtrest.api.dto.ProductDto;
import be.technocite.jwtrest.model.Product;
import be.technocite.jwtrest.repository.ProductRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.function.Function;

import static java.util.stream.Collectors.toList;

@Service
public class ProductService implements Function<Product, ProductDto> {

    @Autowired
    private ProductRepository productRepository;

    public List<ProductDto> findAll() {
        return productRepository.findAll()
                .stream()
                .map(this)
                .collect(toList());
    }

    public ProductDto save(Product product) {
        return apply(productRepository.save(product));
    }

    public ProductDto findById(String id) {
        return apply(productRepository.findById(id));

    }

    @Override
    public ProductDto apply(Product product) {
        return new ProductDto(
                product.getId(),
                product.getName(),
                product.getPrice());
    }
}
