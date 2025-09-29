// src/main/java/br/com/fiap/nextpark/controller/VagaController.java
package br.com.fiap.nextpark.controller;

import br.com.fiap.nextpark.model.entity.Vaga;
import br.com.fiap.nextpark.model.enums.StatusVaga;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import br.com.fiap.nextpark.service.VagaService;

@Controller
@RequestMapping("/vaga")
@PreAuthorize("hasRole('GERENTE')")
public class VagaController {
    private final VagaService vagaService;
    public VagaController(VagaService v){ this.vagaService=v; }

    @GetMapping
    public String list(Model model){
        model.addAttribute("vagas", vagaService.listarTodas()); return "vaga/list";
    }

    @GetMapping("/nova")
    public String nova(Model model){
        model.addAttribute("vaga", new Vaga()); model.addAttribute("status", StatusVaga.values()); return "vaga/form";
    }

    @PostMapping public
    String criar (@ModelAttribute Vaga v, RedirectAttributes ra){ vagaService.salvar(v); ra.addFlashAttribute("msg","Vaga criada!");
        return "redirect:/vaga";
    }

    @GetMapping("/{id}/editar")
    public String editar(@PathVariable Long id, Model model){ model.addAttribute("vaga", vagaService.obter(id));
        model.addAttribute("status", StatusVaga.values()); return "vaga/form";
    }

    @PostMapping("/{id}")
    public String atualizar(@PathVariable Long id, @ModelAttribute Vaga v, RedirectAttributes ra){
        vagaService.atualizar(id, v); ra.addFlashAttribute("msg","Vaga atualizada!"); return "redirect:/vaga";
    }

    @PostMapping("/{id}/delete")
    public String deletar(@PathVariable Long id, RedirectAttributes ra){
        vagaService.deletar(id); ra.addFlashAttribute("msg","Vaga excluída!"); return "redirect:/vaga";
    }
}
