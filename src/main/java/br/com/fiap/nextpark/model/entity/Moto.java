package br.com.fiap.nextpark.model.entity;

import br.com.fiap.nextpark.model.enums.StatusMoto;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name="MOTOS")
@SequenceGenerator(name="MOTOS_SEQ", sequenceName="MOTOS_SEQ", allocationSize=1)
public class Moto {
    @Id
    @GeneratedValue(strategy=GenerationType.SEQUENCE, generator="MOTOS_SEQ")
    private Long id;

    @Column(name="PLACA", unique=true, nullable=false)
    private String placa;

    @Column(name="MODELO", nullable=false)
    private String modelo;

    @Enumerated(EnumType.STRING)
    @Column(name="STATUS", nullable=false)
    private StatusMoto status;

    @Column(name="OWNER_USER_ID", nullable=false)
    private Long ownerUserId;

    @ManyToOne(fetch=FetchType.EAGER)
    @JoinColumn(name="VAGA_ID")
    private Vaga vaga;


}
