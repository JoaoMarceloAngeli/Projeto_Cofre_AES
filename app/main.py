from fastapi import FastAPI, Header, HTTPException
import uuid
from datetime import datetime, timezone

# Importando os módulos locais (você construiu banco e modelos; João construiu cripto)
from app import banco, modelos, cripto

app = FastAPI(title="Cofre de Senhas AES-GCM")

# --- FUNÇÃO AUXILIAR DE VERIFICAÇÃO ---
# O roteiro exige que o verificador seja conferido ANTES de tocar no segredo em toda rota que exige senha.
def validar_e_obter_chave(cofre_id: str, senha_mestra: str) -> bytes:
    cofre = banco.buscar_cofre(cofre_id)
    if not cofre:
        raise HTTPException(status_code=404, detail="Cofre não encontrado")
    
    # 1. Recupera o sal (decodificando de base64) e as iterações
    sal_bytes = cripto.de_b64(cofre["kdf_sal"])
    iteracoes = cofre["kdf_iteracoes"]
    
    # 2. Deriva a chave
    chave = cripto.derivar_chave(senha_mestra, sal_bytes, iteracoes)
    
    # 3. Confere a senha-mestra usando o verificador
    # Se falhar, o status exigido é 401
    senha_ok = cripto.senha_mestra_correta(
        chave,
        cofre["verificador_nonce"],
        cofre["verificador_criptograma"],
        cofre["verificador_etiqueta"],
        cofre_id
    )
    if not senha_ok:
        raise HTTPException(status_code=401, detail="Senha-mestra incorreta")
    
    return chave

# --- 1. CRIAR COFRE ---
@app.post("/cofres", status_code=201)
def criar_cofre(novo_cofre: modelos.NovoCofre):
    # Gera IDs e parâmetros criptográficos
    cofre_id = str(uuid.uuid4())
    sal_bytes = cripto.gerar_sal()
    iteracoes = cripto.ITERACOES_PADRAO
    
    # Deriva a chave inicial
    chave = cripto.derivar_chave(novo_cofre.senha_mestra, sal_bytes, iteracoes)
    
    # Cria o verificador
    v_nonce, v_cripto, v_etiqueta = cripto.criar_verificador(chave, cofre_id)
    
    # Monta o dicionário para o banco
    dados = {
        "id": cofre_id,
        "nome": novo_cofre.nome,
        "kdf_sal": cripto.para_b64(sal_bytes),
        "kdf_iteracoes": iteracoes,
        "verificador_nonce": v_nonce,
        "verificador_criptograma": v_cripto,
        "verificador_etiqueta": v_etiqueta
    }
    
    banco.inserir_cofre(dados)
    return {"id": cofre_id}

# --- 2. ABRIR COFRE ---
@app.post("/cofres/{cofre_id}/abrir", status_code=200)
def abrir_cofre(cofre_id: str, x_senha_mestra: str = Header(...)):
    # Apenas chama a validação. Se passar, retorna 200. Se falhar, a função já levanta o 401.
    validar_e_obter_chave(cofre_id, x_senha_mestra)
    return {"mensagem": "Cofre aberto com sucesso"}

# --- 3. CRIAR SEGREDO ---
@app.post("/cofres/{cofre_id}/segredos", status_code=201)
def criar_segredo(cofre_id: str, segredo: modelos.NovoSegredo, x_senha_mestra: str = Header(...)):
    chave = validar_e_obter_chave(cofre_id, x_senha_mestra)
    
    segredo_id = str(uuid.uuid4())
    aad = f"{cofre_id}|{segredo_id}".encode()
    
    # Cifra a senha
    nonce, criptograma, etiqueta = cripto.cifrar(chave, segredo.senha, aad)
    
    dados = {
        "id": segredo_id,
        "cofre_id": cofre_id,
        "titulo": segredo.titulo,
        "usuario": segredo.usuario,
        "url": segredo.url,
        "nonce": nonce,
        "criptograma": criptograma,
        "etiqueta": etiqueta
    }
    
    banco.inserir_segredo(dados)
    return {"id": segredo_id}

# --- 4. LISTAR SEGREDOS ---
@app.get("/cofres/{cofre_id}/segredos", status_code=200)
def listar_segredos(cofre_id: str, x_senha_mestra: str = Header(...)):
    # Exige a senha mestra para listar, como manda a regra
    validar_e_obter_chave(cofre_id, x_senha_mestra)
    
    # O banco já está programado para não devolver as colunas sensíveis (nonce, cripto, etiqueta)
    segredos = banco.listar_segredos(cofre_id)
    return segredos

# --- 5. LER SEGREDO ESPECÍFICO ---
@app.get("/cofres/{cofre_id}/segredos/{segredo_id}", status_code=200)
def ler_segredo(cofre_id: str, segredo_id: str, x_senha_mestra: str = Header(...)):
    chave = validar_e_obter_chave(cofre_id, x_senha_mestra)
    
    registro = banco.buscar_segredo(segredo_id)
    if not registro or registro["cofre_id"] != cofre_id:
        raise HTTPException(status_code=404, detail="Segredo não encontrado")
    
    aad = f"{cofre_id}|{segredo_id}".encode()
    
    try:
        senha_clara = cripto.decifrar(
            chave,
            registro["nonce"],
            registro["criptograma"],
            registro["etiqueta"],
            aad
        )
        return {"senha": senha_clara}
    except ValueError:
        # A etiqueta falhou na decifragem: registro adulterado (código 500)
        raise HTTPException(status_code=500, detail="Falha de integridade: registro adulterado")

# --- 6. ATUALIZAR SEGREDO ---
@app.put("/cofres/{cofre_id}/segredos/{segredo_id}", status_code=200)
def atualizar_segredo(cofre_id: str, segredo_id: str, segredo: modelos.NovoSegredo, x_senha_mestra: str = Header(...)):
    chave = validar_e_obter_chave(cofre_id, x_senha_mestra)
    
    registro_atual = banco.buscar_segredo(segredo_id)
    if not registro_atual or registro_atual["cofre_id"] != cofre_id:
        raise HTTPException(status_code=404, detail="Segredo não encontrado")
    
    aad = f"{cofre_id}|{segredo_id}".encode()
    
    # O GCM vai gerar um NOVO nonce automaticamente dentro do cripto.cifrar
    novo_nonce, novo_criptograma, nova_etiqueta = cripto.cifrar(chave, segredo.senha, aad)
    
    dados_atualizados = {
        "titulo": segredo.titulo,
        "usuario": segredo.usuario,
        "url": segredo.url,
        "nonce": novo_nonce,
        "criptograma": novo_criptograma,
        "etiqueta": nova_etiqueta,
        "atualizado_em": datetime.now(timezone.utc).isoformat()
    }
    
    banco.atualizar_segredo(segredo_id, dados_atualizados)
    return {"mensagem": "Segredo atualizado com sucesso"}

# --- 7. DELETAR SEGREDO ---
@app.delete("/cofres/{cofre_id}/segredos/{segredo_id}", status_code=200)
def deletar_segredo(cofre_id: str, segredo_id: str, x_senha_mestra: str = Header(...)):
    validar_e_obter_chave(cofre_id, x_senha_mestra)
    
    registro = banco.buscar_segredo(segredo_id)
    if not registro or registro["cofre_id"] != cofre_id:
        raise HTTPException(status_code=404, detail="Segredo não encontrado")
    
    banco.remover_segredo(segredo_id)
    return {"mensagem": "Segredo removido com sucesso"}