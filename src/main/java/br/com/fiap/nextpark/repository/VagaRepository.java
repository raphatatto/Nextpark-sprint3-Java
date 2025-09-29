package br.com.fiap.nextpark.repository;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import br.com.fiap.nextpark.model.entity.Vaga;
import br.com.fiap.nextpark.model.enums.StatusVaga;

public interface VagaRepository extends JpaRepository<Vaga, Long> {
    List<Vaga> findByStatus(StatusVaga status);
    boolean existsByCodigoIgnoreCase(String codigo);

}
