package br.com.fiap.nextpark.repository;

import java.util.List;
import java.util.Optional;

import br.com.fiap.nextpark.model.entity.Moto;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;


public interface MotoRepository extends JpaRepository<Moto, Long> {

    // busca geral (gerente)
    @Query("""
         select m from Moto m
         where (:q is null or :q = ''
                or lower(m.placa) like lower(concat('%', :q, '%'))
                or lower(m.modelo) like lower(concat('%', :q, '%')))
         order by m.id desc
         """)
    List<Moto> searchAll(String q);

    // busca do cliente por ownerUserId
    @Query("""
  select m from Moto m
  left join fetch m.vaga v
  where m.ownerUserId = :ownerId
    and ( :q is null or :q = ''
          or lower(m.placa) like lower(concat('%', :q, '%'))
          or lower(m.modelo) like lower(concat('%', :q, '%')) )
  order by m.id desc
  """)
    List<Moto> searchMine(Long ownerId, String q);
    boolean existsByPlacaIgnoreCase(String placa);
    boolean existsByIdAndOwnerUserId(Long id, Long ownerId);

    @Query("select m from Moto m left join fetch m.vaga where m.id = :id")
    Optional<Moto> findByIdFetchVaga(Long id);
    List<Moto> findByVaga_Id(Long vagaId);
}
