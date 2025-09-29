package br.com.fiap.nextpark.model.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@Entity
@Table(name="HIST_MOV")
@SequenceGenerator(name="HIST_MOV_SEQ", sequenceName="HIST_MOV_SEQ", allocationSize=1)
public class HistoricoMovimentacao {
    @Id
    @GeneratedValue(strategy=GenerationType.SEQUENCE, generator="HIST_MOV_SEQ")
    private Long id;

    @ManyToOne(optional=false) @JoinColumn(name="MOTO_ID")
    private Moto moto;

    @ManyToOne @JoinColumn(name="ORIGEM_VAGA_ID")
    private Vaga origem;

    @ManyToOne @JoinColumn(name="DESTINO_VAGA_ID")
    private Vaga destino;

    @Column(name="ACAO", nullable=false)
    private String acao;

    @Column(name="USUARIO", nullable=false)
    private String usuario;

    @Column(name="CREATED_AT", nullable=false)
    private LocalDateTime createdAt = LocalDateTime.now();

}
