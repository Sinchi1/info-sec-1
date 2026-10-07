package ru.itmo.secureapi;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.HtmlUtils;

@RestController
public class ApiController {
    private final NotesRepository repository;
    private final PasswordEncoder passwords;
    private final JwtEncoder tokens;
    private final String dummyHash;

    public ApiController(NotesRepository repository, PasswordEncoder passwords, JwtEncoder tokens) {
        this.repository = repository;
        this.passwords = passwords;
        this.tokens = tokens;
        this.dummyHash = passwords.encode(UUID.randomUUID().toString());
    }

    @PostMapping("/auth/login")
    public TokenResponse login(@Valid @RequestBody LoginRequest request) {
        if (request.password().getBytes(StandardCharsets.UTF_8).length > 72) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        String hash = repository.passwordHash(request.login());
        boolean valid = passwords.matches(request.password(), hash == null ? dummyHash : hash);
        if (!valid || hash == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder().issuer(SecurityConfig.ISSUER)
                .audience(List.of(SecurityConfig.AUDIENCE)).subject(request.login())
                .issuedAt(now).expiresAt(now.plusSeconds(900)).build();
        String jwt = tokens.encode(JwtEncoderParameters.from(
                JwsHeader.with(MacAlgorithm.HS256).build(), claims)).getTokenValue();
        return new TokenResponse(jwt, "Bearer", 900);
    }

    @GetMapping("/api/data")
    public List<NotesRepository.Note> data(@AuthenticationPrincipal Jwt jwt) {
        return repository.findByOwner(jwt.getSubject()).stream().map(ApiController::escape).toList();
    }

    @PostMapping("/auth/register")
    @ResponseStatus(HttpStatus.CREATED)
    public RegisterResponse register(@Valid @RequestBody RegisterRequest request) {
        if (request.password().getBytes(StandardCharsets.UTF_8).length > 72) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        try {
            repository.createUser(request.login(), passwords.encode(request.password()));
        } catch (DuplicateKeyException exception) {
            // The database primary key also prevents concurrent registrations of one login.
            throw new ResponseStatusException(HttpStatus.CONFLICT);
        }
        return new RegisterResponse(HtmlUtils.htmlEscape(request.login(), "UTF-8"));
    }

    private static NotesRepository.Note escape(NotesRepository.Note note) {
        return new NotesRepository.Note(note.id(), HtmlUtils.htmlEscape(note.content(), "UTF-8"));
    }

    public record LoginRequest(@NotBlank @Size(max = 64) String login,
                               @NotBlank @Size(max = 72) String password) {}
    public record RegisterRequest(@NotBlank @Size(max = 64) String login,
                                  @NotBlank @Size(min = 12, max = 72) String password) {}
    public record RegisterResponse(String login) {}
    public record TokenResponse(String accessToken, String tokenType, long expiresIn) {}
}
