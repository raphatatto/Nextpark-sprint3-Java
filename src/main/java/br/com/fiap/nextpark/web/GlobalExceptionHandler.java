package br.com.fiap.nextpark.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.NestedExceptionUtils;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@ControllerAdvice(annotations = Controller.class)
public class GlobalExceptionHandler {

    private String back(HttpServletRequest req) {
        String ref = req.getHeader("Referer");
        return (ref != null && !ref.isBlank()) ? "redirect:" + ref : "redirect:/";
    }

    // Regras de negócio (mensagens amigáveis)
    @ExceptionHandler(IllegalArgumentException.class)
    public String handleIllegal(IllegalArgumentException ex, HttpServletRequest req, RedirectAttributes ra) {
        ra.addFlashAttribute("erro", ex.getMessage());
        return back(req);
    }

    // Sem permissão
    @ExceptionHandler(AccessDeniedException.class)
    public String handleDenied(AccessDeniedException ex, HttpServletRequest req, RedirectAttributes ra) {
        ra.addFlashAttribute("erro", "Acesso negado.");
        return "redirect:/login";
    }

    // Banco (ex.: UNIQUE/PK) — fallback se escapar a validação do service
    @ExceptionHandler(DataIntegrityViolationException.class)
    public String handleDataIntegrity(DataIntegrityViolationException ex, HttpServletRequest req, RedirectAttributes ra) {
        String msg = "Dados duplicados / restrição violada.";
        Throwable root = NestedExceptionUtils.getMostSpecificCause(ex);
        String m = (root != null ? root.getMessage() : ex.getMessage());
        if (m != null) {
            String low = m.toLowerCase();
            if (low.contains("placa")) msg = "Placa já cadastrada";
            if (low.contains("codigo") && low.contains("vaga")) msg = "Código de vaga já cadastrado";
            if (low.contains("uk_motos_placa")) msg = "Placa já cadastrada";
            if (low.contains("uk_vagas_codigo")) msg = "Código de vaga já cadastrado";
        }
        ra.addFlashAttribute("erro", msg);
        return back(req);
    }

    // Qualquer outra Exception -> volta com mensagem genérica
    @ExceptionHandler(Exception.class)
    public String handleOther(Exception ex, HttpServletRequest req, RedirectAttributes ra) {
        ra.addFlashAttribute("erro", "Ops! Algo deu errado.");
        return back(req);
    }
}
