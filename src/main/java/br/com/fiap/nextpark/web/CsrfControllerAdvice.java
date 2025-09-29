package br.com.fiap.nextpark.web;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@ControllerAdvice(annotations = Controller.class)
public class CsrfControllerAdvice {

    @ModelAttribute("_csrf")
    public CsrfToken csrfToken() {
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes instanceof ServletRequestAttributes servletRequestAttributes) {
            return (CsrfToken) servletRequestAttributes.getRequest().getAttribute(CsrfToken.class.getName());
        }
        return null;
    }
}
