package br.com.fiap.nextpark.controller;

import br.com.fiap.nextpark.security.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
public class RegisterController {

    private final UsuarioRepository repo;
    private final PasswordEncoder encoder;

    public RegisterController(UsuarioRepository repo, PasswordEncoder encoder){
        this.repo = repo; this.encoder = encoder;
    }

    @GetMapping("/register")
    public String form(Model model){
        model.addAttribute("usuario", new Usuario());
        return "auth/register";
    }

    @PostMapping("/register")
    public String registrar(@ModelAttribute Usuario u){
        u.setPassword(encoder.encode(u.getPassword()));
        u.setRole(Role.CLIENTE);
        repo.save(u);
        return "redirect:/login?registered";
    }
}
