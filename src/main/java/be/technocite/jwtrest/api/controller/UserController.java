package be.technocite.jwtrest.api.controller;

import be.technocite.jwtrest.api.dto.RegisterUserCommand;
import be.technocite.jwtrest.config.JwtTokenProvider;
import be.technocite.jwtrest.model.User;
import be.technocite.jwtrest.repository.UserRepository;
import be.technocite.jwtrest.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class UserController {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserService userDetailsService;

    @PostMapping("/register")
    public ResponseEntity register(@RequestBody RegisterUserCommand command) {
        User user = userDetailsService.findByEmail(command.getEmail());
        if (user != null) {
            throw new BadCredentialsException("User with email: " + command.getEmail() + " already exists");
        } else {
            userDetailsService.registerUser(command);
            Map<Object, Object> model = new HashMap<>();
            model.put("message", "User registered successfully");
            return ResponseEntity.ok(model);
        }
    }
}
