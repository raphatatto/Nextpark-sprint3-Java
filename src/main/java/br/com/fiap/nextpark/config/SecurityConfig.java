package br.com.fiap.nextpark.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    // SecurityConfig.java
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login", "/register", "/css/**", "/js/**", "/images/**").permitAll()
                        .requestMatchers(org.springframework.http.HttpMethod.POST, "/register").permitAll() // garante POST
                        .requestMatchers("/vaga/**").hasRole("GERENTE")
                        .anyRequest().authenticated()
                )
                .formLogin(f -> f
                        .loginPage("/login")
                        .defaultSuccessUrl("/", true)
                        .permitAll()
                )
                .logout(l -> l.logoutUrl("/logout").logoutSuccessUrl("/login?logout").permitAll())
                .csrf(csrf -> csrf  // mantenha CSRF ligado; é mais seguro
                        // se você usa endpoints JSON/API, ignore-os aqui
                        .ignoringRequestMatchers("/api/**")
                );
        return http.build();
    }


    @Bean
    PasswordEncoder passwordEncoder() {
        return org.springframework.security.crypto.factory.PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
