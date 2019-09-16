package be.technocite.jwtrest.repository;

import be.technocite.jwtrest.model.User;

public interface UserRepository {

    User findByEmail(String email);

    User save(User user);
}
