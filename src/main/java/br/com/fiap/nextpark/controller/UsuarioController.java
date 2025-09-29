package br.com.fiap.nextpark.controller;

import br.com.fiap.nextpark.security.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/usuario")
@PreAuthorize("hasRole('GERENTE')")
public class UsuarioController {

    private final UsuarioRepository repo;
    public UsuarioController(UsuarioRepository repo){ this.repo = repo; }

    @PostMapping("/{id}/promover")
    public String promover(@PathVariable Long id){
        Usuario u = repo.findById(id).orElseThrow();
        u.setRole(Role.GERENTE);
        repo.save(u);
        return "redirect:/";
    }
}
