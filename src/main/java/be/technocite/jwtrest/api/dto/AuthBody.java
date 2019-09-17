package be.technocite.jwtrest.api.dto;

/*utilisé pour le login seulement*/
public class AuthBody {

    private String email;
    private String password;

    protected AuthBody() {
    }

    public String getEmail() {
        return email;
    }

    public String getPassword() {
        return password;
    }
}
