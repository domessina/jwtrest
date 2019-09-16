package be.technocite.jwtrest.api.dto;

public class ProductDto {

    private String id;
    private String name;
    private double price;

    protected ProductDto() {
    }

    public ProductDto(String id, String name, double price) {
        this.id = id;
        this.name = name;
        this.price = price;
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public double getPrice() {
        return price;
    }
}
