package br.com.fiap.nextpark.service;

import br.com.fiap.nextpark.model.entity.*;
import br.com.fiap.nextpark.model.enums.*;
import br.com.fiap.nextpark.repository.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class PatioService {
    private final MotoRepository motoRepo;
    private final VagaRepository vagaRepo;
    private final HistoricoMovimentacaoRepository histRepo;

    public PatioService(MotoRepository m, VagaRepository v, HistoricoMovimentacaoRepository h){
        this.motoRepo = m; this.vagaRepo = v; this.histRepo = h;
    }

    @Transactional
    public void alocarMoto(Long motoId, Long vagaId, String usuario){
        Moto m = motoRepo.findById(motoId).orElseThrow();
        Vaga v = vagaRepo.findById(vagaId).orElseThrow();
        if (v.getStatus() != StatusVaga.LIVRE) throw new IllegalStateException("Vaga ocupada");
        if (m.getVaga() != null) m.getVaga().setStatus(StatusVaga.LIVRE);
        v.setStatus(StatusVaga.OCUPADA);
        Vaga origem = m.getVaga();
        m.setVaga(v);
        m.setStatus(StatusMoto.ALOCADA);
        salvarHist(m, origem, v, "ALOCAR", usuario);
    }

    @Transactional
    public void desalocarMoto(Long motoId, String usuario){
        Moto m = motoRepo.findById(motoId).orElseThrow();
        Vaga origem = m.getVaga();
        if (origem != null) origem.setStatus(StatusVaga.LIVRE);
        m.setVaga(null);
        m.setStatus(StatusMoto.DESALOCADA);
        salvarHist(m, origem, null, "DESALOCAR", usuario);
    }

    @Transactional
    public void transferirMoto(Long motoId, Long destinoId, String usuario){
        Moto m = motoRepo.findById(motoId).orElseThrow();
        Vaga origem = m.getVaga();
        if (origem == null) throw new IllegalStateException("Moto não está alocada");
        Vaga destino = vagaRepo.findById(destinoId).orElseThrow();
        if (destino.getStatus() != StatusVaga.LIVRE) throw new IllegalStateException("Destino ocupado");
        origem.setStatus(StatusVaga.LIVRE);
        destino.setStatus(StatusVaga.OCUPADA);
        m.setVaga(destino);
        m.setStatus(StatusMoto.ALOCADA);
        salvarHist(m, origem, destino, "TRANSFERIR", usuario);
    }

    @Transactional
    public void excluirMotoLiberandoVaga(Long motoId, String usuario){
        Moto m = motoRepo.findById(motoId).orElseThrow();
        Vaga origem = m.getVaga();
        if (origem != null) origem.setStatus(StatusVaga.LIVRE);
        salvarHist(m, origem, null, "EXCLUIR_MOTO", usuario);
        motoRepo.delete(m);
    }

    @Transactional
    public void excluirVagaDesalocandoMoto(Long vagaId, String usuario){
        Vaga v = vagaRepo.findById(vagaId).orElseThrow();
        motoRepo.findAll().stream().filter(m -> v.equals(m.getVaga())).forEach(m -> {
            m.setVaga(null);
            m.setStatus(StatusMoto.DESALOCADA);
        });
        salvarHist(null, v, null, "EXCLUIR_VAGA", usuario);
        vagaRepo.delete(v);
    }

    private void salvarHist(Moto m, Vaga origem, Vaga destino, String acao, String usuario){
        HistoricoMovimentacao h = new HistoricoMovimentacao();
        h.setMoto(m);
        h.setOrigem(origem);
        h.setDestino(destino);
        h.setAcao(acao);
        h.setUsuario(usuario);
        histRepo.save(h);
    }
}
