package be.technocite.jwtrest.repository.impl;

import be.technocite.jwtrest.model.Product;
import be.technocite.jwtrest.repository.ProductRepository;
import org.springframework.stereotype.Repository;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.List;

import static java.util.Arrays.asList;
import static org.hibernate.validator.internal.util.CollectionHelper.newArrayList;

@Repository
public class ProductRepositoryImpl implements ProductRepository {

    private ArrayList<Product> products = newArrayList();

    @Override
    public Product findById(String id) {
        return products.stream()
                .filter(product -> product.getId().equals(id))
                .findFirst()
                .orElse(null);
    }

    @Override
    public Product save(Product product) {
        if (findById(product.getId()) == null) {
            products.add(product);
        } else {
            products.remove(product);
            products.add(product);
        }
        return findById(product.getId());
    }

    @Override
    public List<Product> findAll() {
        return products;
    }

    @Override
    public boolean delete(Product product) {
        return products.remove(product);
    }

    @PostConstruct
    private void onPostConstruct() {
        products.addAll(asList(
                new Product("id1", "banane", 10.5),
                new Product("id2", "barbie", 666)
        ));
    }
}
