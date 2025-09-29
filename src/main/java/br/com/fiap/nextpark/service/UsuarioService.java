package br.com.fiap.nextpark.service;

import org.springframework.stereotype.Service;
import br.com.fiap.nextpark.security.Usuario;
import br.com.fiap.nextpark.security.UsuarioRepository;

@Service
public class UsuarioService {
    private final UsuarioRepository repo;

    public UsuarioService(UsuarioRepository repo) { this.repo = repo; }

    public Usuario requireByUsername(String username) {
        return repo.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("Usuário não encontrado: " + username));
    }
}
