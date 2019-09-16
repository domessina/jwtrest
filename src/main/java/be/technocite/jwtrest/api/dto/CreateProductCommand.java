package be.technocite.jwtrest.api.dto;

public class CreateProductCommand {

    private String name;
    private double price;

    protected CreateProductCommand() {
    }

    public String getName() {
        return name;
    }

    public double getPrice() {
        return price;
    }
}
