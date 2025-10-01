package br.com.fiap.nextpark.config;

import br.com.fiap.nextpark.security.Role;
import br.com.fiap.nextpark.security.Usuario;
import br.com.fiap.nextpark.security.UsuarioRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class AdminUserInitializer implements CommandLineRunner {

    private static final Logger logger = LoggerFactory.getLogger(AdminUserInitializer.class);

    private final UsuarioRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final String username;
    private final String rawPassword;

    public AdminUserInitializer(
            UsuarioRepository repository,
            PasswordEncoder passwordEncoder,
            @Value("${app.security.admin.username:gerente}") String username,
            @Value("${app.security.admin.password:gerente123}") String rawPassword
    ) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.username = username;
        this.rawPassword = rawPassword;
    }

    @Override
    @Transactional
    public void run(String... args) {
        repository.findByUsername(username)
                .ifPresentOrElse(this::ensurePasswordIsEncoded, this::createDefaultAdminUser);
    }

    private void ensurePasswordIsEncoded(Usuario usuario) {
        if (needsEncoding(usuario.getPassword())) {
            usuario.setPassword(passwordEncoder.encode(rawPassword));
            usuario.setRole(Role.GERENTE);
            repository.save(usuario);
            logger.info("Updated default admin user '{}' password using configured credentials.", username);
        }
    }

    private void createDefaultAdminUser() {
        Usuario usuario = new Usuario();
        usuario.setUsername(username);
        usuario.setPassword(passwordEncoder.encode(rawPassword));
        usuario.setRole(Role.GERENTE);
        repository.save(usuario);
        logger.info("Created default admin user '{}' with configured credentials.", username);
    }

    private boolean needsEncoding(String password) {
        if (password == null || password.isBlank()) {
            return true;
        }
        if (password.contains("COLE_SEU_HASH_AQUI")) {
            return true;
        }
        return !password.startsWith("{");
    }
}
