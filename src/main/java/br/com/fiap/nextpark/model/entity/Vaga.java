package br.com.fiap.nextpark.model.entity;

import br.com.fiap.nextpark.model.enums.StatusVaga;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name="VAGAS")
@SequenceGenerator(name="VAGAS_SEQ", sequenceName="VAGAS_SEQ", allocationSize=1)
public class Vaga {
    @Id
    @GeneratedValue(strategy=GenerationType.SEQUENCE, generator="VAGAS_SEQ")
    private Long id;

    @Column(name="CODIGO", unique=true, nullable=false)
    private String codigo;

    @Enumerated(EnumType.STRING)
    @Column(name="STATUS", nullable=false)
    private StatusVaga status;

}
