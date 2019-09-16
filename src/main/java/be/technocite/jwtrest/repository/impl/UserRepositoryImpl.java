package be.technocite.jwtrest.repository.impl;

import be.technocite.jwtrest.model.User;
import be.technocite.jwtrest.repository.UserRepository;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;

import static org.hibernate.validator.internal.util.CollectionHelper.newArrayList;

@Repository
public class UserRepositoryImpl implements UserRepository {

    private ArrayList<User> users = newArrayList();

    @Override
    public User findByEmail(String email) {
        return users.stream()
                .filter(user -> user.getEmail().equals(email))
                .findFirst()

                .orElse(null);
    }

    @Override
    public User save(User user) {
        if(findByEmail(user.getEmail()) == null) {
            users.add(user);
        }else {
            users.remove(user);
            users.add(user);
        }
        return findByEmail(user.getEmail());
    }
}
