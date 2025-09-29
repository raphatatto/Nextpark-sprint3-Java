package br.com.fiap.nextpark.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class RedirectController {

    @GetMapping("/motos")
    public String motos() { return "redirect:/moto"; }

    @GetMapping("/vagas")
    public String vagas() { return "redirect:/vaga"; }

    @GetMapping("/alocacoes")
    public String alocacoes() { return "redirect:/moto"; }

    @GetMapping("/localizar")
    public String localizar() { return "redirect:/moto"; }
}
