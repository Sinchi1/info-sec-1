package org.truskovski;

import java.util.List;
import java.util.UUID;

import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class NotesRepository {

    private final JdbcTemplate jdbc;

    public void createUser(String username, String hash) {
        jdbc.update(
                "INSERT INTO app_users(username, password_hash) VALUES (?, ?)",
                username,
                hash
        );
    }

    public String passwordHash(String username) {
        return jdbc.query(
                "SELECT password_hash FROM app_users WHERE username = ?",
                (rs, row) -> rs.getString(1),
                username
        ).stream().findFirst().orElse(null);
    }

    public List<Note> findByOwner(String owner) {
        return jdbc.query(
                "SELECT id, content FROM notes WHERE owner = ? ORDER BY id",
                (rs, row) -> new Note(rs.getObject("id", UUID.class), rs.getString("content")),
                owner
        );
    }

    public Note create(String owner, String content) {
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO notes(id, owner, content) VALUES (?, ?, ?)", id, owner, content);
        return new Note(id, content);
    }

    public record Note(UUID id, String content) {
    }
}
