package org.truskovski;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import jakarta.annotation.PostConstruct;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.HtmlUtils;

@RestController
@RequiredArgsConstructor
public class ApiController {

    private static final int MAX_PASSWORD_BYTES = 72;
    private static final long TOKEN_LIFETIME_SECONDS = 900;

    private final NotesRepository repository;
    private final PasswordEncoder passwords;
    private final JwtEncoder tokens;
    private String dummyHash;

    @PostConstruct
    void initializeDummyHash() {
        dummyHash = passwords.encode(UUID.randomUUID().toString());
    }

    @PostMapping("/auth/login")
    public TokenResponse login(@Valid @RequestBody LoginRequest request) {
        validatePasswordLength(request.password());

        String hash = repository.passwordHash(request.login());
        boolean valid = passwords.matches(request.password(), hash == null ? dummyHash : hash);
        if (!valid || hash == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }

        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(SecurityConfig.ISSUER)
                .audience(List.of(SecurityConfig.AUDIENCE))
                .subject(request.login())
                .issuedAt(now)
                .expiresAt(now.plusSeconds(TOKEN_LIFETIME_SECONDS))
                .build();
        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        String jwt = tokens.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();

        return new TokenResponse(jwt, "Bearer", TOKEN_LIFETIME_SECONDS);
    }

    @GetMapping("/api/data")
    public List<NotesRepository.Note> data(@AuthenticationPrincipal Jwt jwt) {
        return repository.findByOwner(jwt.getSubject()).stream()
                .map(ApiController::escape)
                .toList();
    }

    @PostMapping("/auth/register")
    @ResponseStatus(HttpStatus.CREATED)
    public RegisterResponse register(@Valid @RequestBody RegisterRequest request) {
        validatePasswordLength(request.password());

        try {
            repository.createUser(request.login(), passwords.encode(request.password()));
        } catch (DuplicateKeyException exception) {
            throw new ResponseStatusException(HttpStatus.CONFLICT);
        }

        return new RegisterResponse(HtmlUtils.htmlEscape(request.login(), "UTF-8"));
    }

    private static void validatePasswordLength(String password) {
        if (password.getBytes(StandardCharsets.UTF_8).length > MAX_PASSWORD_BYTES) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
    }

    private static NotesRepository.Note escape(NotesRepository.Note note) {
        return new NotesRepository.Note(note.id(), HtmlUtils.htmlEscape(note.content(), "UTF-8"));
    }

    public record LoginRequest(
            @NotBlank @Size(max = 64) String login,
            @NotBlank @Size(max = 72) String password
    ) {
    }

    public record RegisterRequest(
            @NotBlank @Size(max = 64) String login,
            @NotBlank @Size(min = 12, max = 72) String password
    ) {
    }

    public record RegisterResponse(String login) {
    }

    public record TokenResponse(String accessToken, String tokenType, long expiresIn) {
    }
}
