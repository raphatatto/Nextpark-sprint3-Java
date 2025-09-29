package br.com.fiap.nextpark.service;

import java.util.List;

import br.com.fiap.nextpark.model.entity.Moto;
import br.com.fiap.nextpark.model.entity.Vaga;
import br.com.fiap.nextpark.model.enums.StatusMoto;
import br.com.fiap.nextpark.model.enums.StatusVaga;
import br.com.fiap.nextpark.repository.MotoRepository;
import br.com.fiap.nextpark.repository.VagaRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


@Service
public class VagaService {

    private final VagaRepository vagaRepo;
    private final MotoRepository motoRepo;

    public VagaService(VagaRepository vagaRepo, MotoRepository motoRepo) {
        this.vagaRepo = vagaRepo; this.motoRepo = motoRepo;
    }

    public List<Vaga> listarTodas() { return vagaRepo.findAll(); }

    @Transactional
    public Vaga salvar(Vaga v) {
        if (v.getStatus() == null) v.setStatus(StatusVaga.LIVRE);
        if (v.getId() == null && vagaRepo.existsByCodigoIgnoreCase(v.getCodigo()))
            throw new IllegalArgumentException("Código de vaga já cadastrado");
        return vagaRepo.save(v);
    }

    public Vaga obter(Long id) { return vagaRepo.findById(id).orElseThrow(); }

    @Transactional
    public Vaga atualizar(Long id, Vaga src) {
        Vaga v = obter(id);
        v.setCodigo(src.getCodigo());
        v.setStatus(src.getStatus());
        return v;
    }

    @Transactional
    public void deletar(Long id) {
        Vaga v = obter(id);
        List<Moto> motos = motoRepo.findByVaga_Id(id);
        for (Moto m : motos) {
            m.setVaga(null);
            m.setStatus(StatusMoto.DESALOCADA);
        }
        motoRepo.saveAll(motos);
        vagaRepo.delete(v);
    }
}
