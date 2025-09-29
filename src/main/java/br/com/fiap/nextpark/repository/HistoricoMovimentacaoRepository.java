package br.com.fiap.nextpark.repository;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import br.com.fiap.nextpark.model.entity.HistoricoMovimentacao;
import org.springframework.data.jpa.repository.Query;

public interface HistoricoMovimentacaoRepository extends JpaRepository<HistoricoMovimentacao, Long> {
    List<HistoricoMovimentacao> findByMoto_IdOrderByCreatedAtDesc(Long motoId);

    @Query("""
  select h from HistoricoMovimentacao h
  left join fetch h.origem
  left join fetch h.destino
  where h.moto.id = :motoId
  order by h.createdAt desc
  """)
    List<HistoricoMovimentacao> findDetalhadoByMotoId(Long motoId);
}
