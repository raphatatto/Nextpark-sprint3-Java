// src/main/java/br/com/fiap/nextpark/controller/MotoController.java
package br.com.fiap.nextpark.controller;

import java.security.Principal;

import br.com.fiap.nextpark.model.entity.Moto;
import br.com.fiap.nextpark.model.enums.StatusMoto;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import br.com.fiap.nextpark.service.MotoService;
import br.com.fiap.nextpark.service.UsuarioService;
import br.com.fiap.nextpark.service.VagaService;

@Controller
@RequestMapping("/moto")
public class MotoController {
    private final MotoService motoService;
    private final VagaService vagaService;
    private final UsuarioService usuarioService;

    public MotoController(MotoService m, VagaService v, UsuarioService u){ this.motoService=m; this.vagaService=v; this.usuarioService=u; }

    @GetMapping
    public String list(@RequestParam(value="q", required=false) String q,
                       Authentication auth, Principal principal, Model model){
        boolean gerente = auth.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_GERENTE"));
        model.addAttribute("motos", motoService.listarPara(principal.getName(), gerente, q));
        model.addAttribute("vagasLivres", vagaService.listarTodas());
        return "moto/list";
    }

    @GetMapping("/nova")
    public String nova(Model model){
        model.addAttribute("moto", new Moto());
        model.addAttribute("status", StatusMoto.values());
        return "moto/form";
    }

    @PostMapping
    public String criar(@ModelAttribute Moto moto, Principal principal, RedirectAttributes ra){
        motoService.criar(principal.getName(), moto);
        ra.addFlashAttribute("msg","Moto criada!");
        return "redirect:/moto";
    }

    @GetMapping("/{id}/editar")
    public String editar(@PathVariable Long id, Model model){
        model.addAttribute("moto", motoService.listarPara("", true, null).stream().filter(m->m.getId().equals(id)).findFirst().orElseThrow());
        model.addAttribute("status", StatusMoto.values());
        return "moto/form";
    }

    @PostMapping("/{id}")
    public String atualizar(@PathVariable Long id, @ModelAttribute Moto src, Principal principal, RedirectAttributes ra){
        motoService.atualizarCliente(principal.getName(), id, src);
        ra.addFlashAttribute("msg","Moto atualizada!");
        return "redirect:/moto";
    }

    @PostMapping("/{id}/delete")
    public String deletar(@PathVariable Long id, Authentication auth, Principal principal, RedirectAttributes ra){
        boolean gerente = auth.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_GERENTE"));
        if (gerente) {
            motoService.deletarGerente(id, principal.getName());
        } else {
            motoService.deletarCliente(principal.getName(), id);
        }
        ra.addFlashAttribute("msg","Moto excluída!");
        return "redirect:/moto";
    }

    @PostMapping("/{id}/desalocar")
    public String desalocar(@PathVariable Long id, Principal principal, RedirectAttributes ra){
        motoService.desalocar(id, principal.getName());
        ra.addFlashAttribute("msg","Moto desalocada!");
        return "redirect:/moto";
    }

    @PostMapping("/{id}/alocar")
    public String alocar(@PathVariable Long id, @RequestParam Long vagaId, Principal principal, RedirectAttributes ra){
        motoService.alocar(id, vagaId, principal.getName());
        ra.addFlashAttribute("msg","Moto alocada/movida!");
        return "redirect:/moto";
    }

    @GetMapping("/{id}/historico")
    public String historico(@PathVariable Long id, Model model){
        model.addAttribute("historico", motoService.historico(id));
        return "moto/historico";
    }
}
