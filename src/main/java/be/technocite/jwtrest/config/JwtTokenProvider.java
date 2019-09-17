package be.technocite.jwtrest.config;

import be.technocite.jwtrest.model.Role;
import be.technocite.jwtrest.service.UserService;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;
import java.util.Set;

@Component
public class JwtTokenProvider {

    private Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);

    private String secret = "secret";
    private long validityMs = 3600000; //1h

    @Autowired
    private UserService userDetailsService;

    @PostConstruct
    private void encodeSecret() {
        //initialisation d'un tableau de bytes vide
        byte[] values = new byte[124];
        //remplissage du tableau avec des bytes générés aléatoirement via un algorythme sécurisé (imprédictible)
        new SecureRandom().nextBytes(values);
        //on encode en base64 les bytes se qui nous retourne une String
        secret = Base64.getEncoder().encodeToString(values);
    }

    public String createToken(String email, Set<Role> roles) {
        //les claims sont les propriétés de la partie payload du token
        Claims claims = Jwts.claims().setSubject(email);
        claims.put("roles", roles);
        Date now = new Date();
        Date expirationDate = new Date(now.getTime() + validityMs);
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact();
    }

    /*extraire le token du header de la requête*/
    String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        // juqu'ici le token ressemble à 'Bearer sekuhse2f54se5fes5f4sejiose5gsg'
        if (bearerToken != null && bearerToken.startsWith("Bearer")) {
            return bearerToken.substring(7, bearerToken.length());
        }
        logger.info("Wrong token : " + bearerToken);
        return null;
    }

    /*vérifier si le token n'est pas périmé*/
    boolean validateToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(token);
            return !claims.getBody().getExpiration().before(new Date());
        } catch (JwtException | IllegalArgumentException e) {
            throw new JwtException("Invalid JWT token");
        }
    }

    /*Créer un objet Authentification qui sera plus tard vérifié comme valide par Spring*/
    Authentication getAuthentication(String token) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(getEmail(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    /*Extraire la propriété sub de la partie payload (claims) du token, elle contient l'email de l'user*/
    private String getEmail(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody().getSubject();
    }
}
