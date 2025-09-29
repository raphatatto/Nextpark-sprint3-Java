package br.com.fiap.nextpark.service;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.List;

import br.com.fiap.nextpark.model.entity.HistoricoMovimentacao;
import br.com.fiap.nextpark.model.entity.Moto;
import br.com.fiap.nextpark.model.entity.Vaga;
import br.com.fiap.nextpark.model.enums.StatusMoto;
import br.com.fiap.nextpark.model.enums.StatusVaga;
import br.com.fiap.nextpark.repository.HistoricoMovimentacaoRepository;
import br.com.fiap.nextpark.repository.MotoRepository;
import br.com.fiap.nextpark.repository.VagaRepository;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class MotoService {

    private final MotoRepository motoRepo;
    private final VagaRepository vagaRepo;
    private final UsuarioService usuarioService;
    private final HistoricoMovimentacaoRepository histRepo;

    public MotoService(MotoRepository motoRepo, VagaRepository vagaRepo,
                       UsuarioService usuarioService, HistoricoMovimentacaoRepository histRepo) {
        this.motoRepo = motoRepo;
        this.vagaRepo = vagaRepo;
        this.usuarioService = usuarioService;
        this.histRepo = histRepo;
    }

    // LISTAGENS
    public List<Moto> listarPara(String username, boolean gerente, String q) {
        if (gerente) return motoRepo.searchAll(q == null ? "" : q);
        Long ownerId = usuarioService.requireByUsername(username).getId();
        return motoRepo.searchMine(ownerId, q);
    }

    // CRUD CLIENTE (verifica dono por ID)
    @Transactional
    public Moto criar(String username, Moto moto) {
        Long ownerId = usuarioService.requireByUsername(username).getId();
        moto.setOwnerUserId(ownerId);
        if (moto.getStatus() == null) moto.setStatus(StatusMoto.DESALOCADA);
        moto.setVaga(null);
        if (motoRepo.existsByPlacaIgnoreCase(moto.getPlaca())) {
            throw new IllegalArgumentException("Placa já cadastrada");
        }
        return motoRepo.save(moto);

    }

    @Transactional
    public Moto atualizarCliente(String username, Long id, Moto src) {
        Moto m = motoRepo.findById(id).orElseThrow();
        Long requesterId = usuarioService.requireByUsername(username).getId();
        if (!m.getOwnerUserId().equals(requesterId))
            throw new AccessDeniedException("Você só pode editar suas motos");

        m.setPlaca(src.getPlaca());
        m.setModelo(src.getModelo());
        m.setStatus(src.getStatus());
        return m;
    }

    @Transactional
    public void deletarCliente(String username, Long id) {
        Moto m = motoRepo.findById(id).orElseThrow();
        Long requesterId = usuarioService.requireByUsername(username).getId();
        if (!m.getOwnerUserId().equals(requesterId))  // <<<<<<<<<<<<<< CORREÇÃO
            throw new AccessDeniedException("Você só pode excluir suas motos");

        if (m.getVaga() != null) {
            Vaga v = m.getVaga();
            v.setStatus(StatusVaga.LIVRE);
            m.setVaga(null);
            m.setStatus(StatusMoto.DESALOCADA);
            vagaRepo.save(v);
        }
        motoRepo.delete(m);
    }

    @Transactional
    public void deletarGerente(Long motoId, String usuarioGerente) {
        Moto m = motoRepo.findById(motoId).orElseThrow();
        Vaga origem = m.getVaga();
        if (origem != null) {
            origem.setStatus(StatusVaga.LIVRE);
            m.setVaga(null);
            m.setStatus(StatusMoto.DESALOCADA);
            registrar(m, origem, null, "EXCLUIR", usuarioGerente);
            vagaRepo.save(origem);
        }
        motoRepo.delete(m);
    }

    // ====== Ações de pátio (GERENTE) ======
    @Transactional
    public void desalocar(Long motoId, String usuarioGerente) {
        Moto m = motoRepo.findById(motoId).orElseThrow();
        Vaga origem = m.getVaga();
        if (origem == null) return;
        origem.setStatus(StatusVaga.LIVRE);
        m.setVaga(null);
        m.setStatus(StatusMoto.DESALOCADA);
        registrar(m, origem, null, "DESALOCAR", usuarioGerente);
    }

    @Transactional
    public void alocar(Long motoId, Long vagaId, String usuarioGerente) {
        Moto m = motoRepo.findById(motoId).orElseThrow();
        Vaga destino = vagaRepo.findById(vagaId).orElseThrow();
        if (destino.getStatus() != StatusVaga.LIVRE)
            throw new IllegalStateException("Vaga não está LIVRE");
        Vaga origem = m.getVaga();
        if (origem != null) origem.setStatus(StatusVaga.LIVRE);
        destino.setStatus(StatusVaga.OCUPADA);
        m.setVaga(destino);
        m.setStatus(StatusMoto.ALOCADA);
        registrar(m, origem, destino, (origem == null ? "ALOCAR" : "TRANSFERIR"), usuarioGerente);
    }

    @Transactional
    public void transferir(Long motoId, Long destinoId, String usuarioGerente) {
        Moto m = motoRepo.findById(motoId).orElseThrow();
        Vaga origem = m.getVaga();
        if (origem == null) throw new IllegalStateException("Moto não está alocada");
        Vaga destino = vagaRepo.findById(destinoId).orElseThrow();
        if (destino.getStatus() != StatusVaga.LIVRE)
            throw new IllegalStateException("Vaga destino não está LIVRE");
        origem.setStatus(StatusVaga.LIVRE);
        destino.setStatus(StatusVaga.OCUPADA);
        m.setVaga(destino);
        m.setStatus(StatusMoto.ALOCADA);
        registrar(m, origem, destino, "TRANSFERIR", usuarioGerente);
    }

    private void registrar(Moto m, Vaga origem, Vaga destino, String acao, String usuario) {
        HistoricoMovimentacao h = new HistoricoMovimentacao();
        h.setMoto(m);
        h.setOrigem(origem);
        h.setDestino(destino);
        h.setAcao(acao);
        h.setUsuario(usuario);
        h.setCreatedAt(LocalDateTime.now());
        histRepo.save(h);
    }

    public List<HistoricoMovimentacao> historico(Long motoId) {
        return histRepo.findByMoto_IdOrderByCreatedAtDesc(motoId);
    }
}
