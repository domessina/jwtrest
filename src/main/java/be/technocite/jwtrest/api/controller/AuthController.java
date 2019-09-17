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
public class AuthController {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserService userDetailsService;

    /*On utilise un nouveau dto autre que User car le client n'a pas le droit de choisir si il
    est enabled
     */
    @PostMapping("/register")
    public ResponseEntity register(@RequestBody RegisterUserCommand command) {
        User user = userDetailsService.findByEmail(command.getEmail());
        if (user != null) {
            throw new BadCredentialsException("User with email: " + command.getEmail() + " already exists");
        } else {
            userDetailsService.registerUser(command);
            //spring va transformer automatiquement cette map en objet JSON,
            //dont la clé sera le nom de la propriété
            Map<Object, Object> model = new HashMap<>();
            model.put("message", "User registered successfully");
            return ResponseEntity.ok(model);
        }
    }
}
