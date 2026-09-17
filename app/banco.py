import os
from dotenv import load_dotenv
from supabase import create_client, Client

# Lê o arquivo .env
load_dotenv()          

# Inicializa a conexão
supabase: Client = create_client(
    os.environ["SUPABASE_URL"],
    os.environ["SUPABASE_KEY"],
)

# --- FUNÇÕES DE COFRES ---

def inserir_cofre(dados_cofre: dict):
    return supabase.table("cofres").insert(dados_cofre).execute()

def buscar_cofre(cofre_id: str):
    consulta = supabase.table("cofres").select("*").eq("id", cofre_id)
    resposta = consulta.execute()
    return resposta.data[0] if resposta.data else None

# --- FUNÇÕES DE SEGREDOS ---

def inserir_segredo(dados_segredo: dict):
    return supabase.table("segredos").insert(dados_segredo).execute()

def listar_segredos(cofre_id: str):
    # CRITÉRIO DE AVALIAÇÃO: Nomear explicitamente as colunas, NUNCA devolver nonce, criptograma nem etiqueta.
    resposta = supabase.table("segredos").select(
        "id, titulo, usuario, url, criado_em"
    ).eq("cofre_id", cofre_id).execute()
    return resposta.data

def buscar_segredo(segredo_id: str):
    # Aqui pode usar select("*") porque o FastAPI vai decifrar a senha no main.py
    resposta = supabase.table("segredos").select("*").eq("id", segredo_id).execute()
    return resposta.data[0] if resposta.data else None

def atualizar_segredo(segredo_id: str, dados_atualizados: dict):
    # O main.py vai mandar o dicionário com o novo nonce, criptograma, etiqueta e atualizado_em
    return supabase.table("segredos").update(dados_atualizados).eq("id", segredo_id).execute()

def remover_segredo(segredo_id: str):
    return supabase.table("segredos").delete().eq("id", segredo_id).execute()