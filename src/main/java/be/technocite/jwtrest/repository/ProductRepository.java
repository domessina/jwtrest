package be.technocite.jwtrest.repository;

import be.technocite.jwtrest.model.Product;

import java.util.List;

public interface ProductRepository {

    //findbyif
    //save
    //findall
    //delete
    //onpistconstryuct

    Product findById(String id);

    Product save(Product product);

    List<Product> findAll();

    boolean delete(Product product);
}
