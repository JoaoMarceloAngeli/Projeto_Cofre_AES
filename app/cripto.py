"""Módulo de criptografia do cofre — dono: João Marcelo.

Esta camada não conhece HTTP nem banco de dados: recebe e devolve tipos
básicos do Python. Toda a política de derivação de chave (PBKDF2) e de
cifragem autenticada (AES-256-GCM) vive aqui e em nenhum outro lugar.
"""

import base64

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# --- PARÂMETROS OBRIGATÓRIOS (§0.7) ---
# Valores fechados pelo enunciado. Alterar qualquer um deles descumpre o requisito.
ITERACOES_PADRAO = 210_000   # mínimo exigido; é gravado no banco a cada cofre
TAMANHO_CHAVE    = 32        # bytes -> AES-256
TAMANHO_SAL      = 16        # bytes, um sal por cofre, guardado em claro
TAMANHO_NONCE    = 12        # bytes, valor recomendado para o GCM

FRASE_VERIFICADORA = "cofre-ok"


# --- AUXILIARES DE CODIFICAÇÃO ---
# O banco guarda os bytes em colunas text, então tudo trafega em Base64.

def para_b64(dados: bytes) -> str:
    return base64.b64encode(dados).decode("ascii")


def de_b64(texto: str) -> bytes:
    return base64.b64decode(texto)


# --- MONTAGEM DO AAD ---
# Precisa ser idêntica na cifragem e na decifragem, senão a etiqueta não confere.
# Existe uma função única para cada formato justamente para não haver duas
# versões da mesma string espalhadas pelo código.

def aad_segredo(cofre_id: str, segredo_id: str) -> bytes:
    """Amarra o criptograma ao par (cofre, segredo) que o contém."""
    return f"{cofre_id}|{segredo_id}".encode()


def aad_verificador(cofre_id: str) -> bytes:
    """O verificador é do cofre inteiro, então o AAD é só o id do cofre."""
    return cofre_id.encode()


# --- DERIVAÇÃO DE CHAVE ---

def derivar_chave(senha_mestra: str, sal: bytes, iteracoes: int) -> bytes:
    """Transforma a senha-mestra numa chave de 32 bytes própria para o AES-256.

    O hmac_hash_module=SHA256 é obrigatório: sem ele a PyCryptodome usa SHA-1
    por padrão, silenciosamente, e o requisito do enunciado deixa de ser cumprido.
    """
    return PBKDF2(
        senha_mestra,
        sal,
        dkLen=TAMANHO_CHAVE,
        count=iteracoes,
        hmac_hash_module=SHA256,
    )


def gerar_sal() -> bytes:
    """Sal novo para um cofre novo. Não é secreto, mas precisa ser aleatório."""
    return get_random_bytes(TAMANHO_SAL)


# --- CIFRAGEM E DECIFRAGEM ---

def cifrar(chave: bytes, texto_claro: str, aad: bytes) -> tuple[str, str, str]:
    """Cifra com AES-GCM e devolve (nonce, criptograma, etiqueta) em Base64.

    O nonce é sorteado aqui dentro, a cada chamada, sem exceção: repetir um
    nonce com a mesma chave é a falha mais grave possível no GCM.
    """
    nonce = get_random_bytes(TAMANHO_NONCE)

    cifra = AES.new(chave, AES.MODE_GCM, nonce=nonce)
    cifra.update(aad)                      # os dados associados entram antes da cifragem

    criptograma, etiqueta = cifra.encrypt_and_digest(texto_claro.encode("utf-8"))

    return para_b64(nonce), para_b64(criptograma), para_b64(etiqueta)


def decifrar(chave: bytes, nonce_b64: str, cripto_b64: str,
             etiqueta_b64: str, aad: bytes) -> str:
    """Decifra verificando a etiqueta. Devolve o texto claro ou levanta ValueError.

    O ValueError ("MAC check failed") NÃO é capturado aqui de propósito: quem
    decide a resposta HTTP é a camada da API, que distingue senha-mestra errada
    (401) de registro adulterado (500).
    """
    nonce       = de_b64(nonce_b64)
    criptograma = de_b64(cripto_b64)
    etiqueta    = de_b64(etiqueta_b64)

    cifra = AES.new(chave, AES.MODE_GCM, nonce=nonce)
    cifra.update(aad)                      # exatamente o mesmo AAD usado ao cifrar

    texto_claro = cifra.decrypt_and_verify(criptograma, etiqueta)

    return texto_claro.decode("utf-8")


# --- VERIFICADOR DO COFRE (canário) ---

def criar_verificador(chave: bytes, cofre_id: str) -> tuple[str, str, str]:
    """Cifra a frase fixa 'cofre-ok' com a chave derivada.

    Guardado no registro do cofre, permite conferir a senha-mestra depois sem
    armazenar a senha nem nada reversível a partir dela.
    """
    return cifrar(chave, FRASE_VERIFICADORA, aad_verificador(cofre_id))


def senha_mestra_correta(chave: bytes, nonce: str, cripto: str,
                         etiqueta: str, cofre_id: str) -> bool:
    """True se a chave derivada abre o verificador do cofre, False caso contrário.

    Aqui o ValueError É capturado: uma senha-mestra errada é uma resposta
    esperada do sistema, não uma falha.
    """
    try:
        frase = decifrar(chave, nonce, cripto, etiqueta, aad_verificador(cofre_id))
    except ValueError:
        return False

    return frase == FRASE_VERIFICADORA
