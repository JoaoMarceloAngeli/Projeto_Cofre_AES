"""Bancada de validação do módulo de criptografia — dono: João Marcelo.

Roda sem HTTP e sem Supabase: exercita app/cripto.py isoladamente para provar
que o módulo está correto antes da integração com a API.

Uso, a partir da RAIZ do projeto e com o ambiente virtual ativo:

    python -m testes.bancada
"""

from app import cripto

# Ids fictícios, no formato uuid que a API usa de verdade.
COFRE_ID   = "3f2b8c10-9e44-4d0b-8a71-6c5d2e0f4a19"
SEGREDO_A  = "b1d7e2a4-05c8-4f39-9b62-77ae3c1d80f5"
SEGREDO_B  = "c9f4a1e7-3b26-4d58-8e03-1a5b9c7d2e64"

SENHA_MESTRA = "senha-mestra-da-equipe"
SENHA_GUARDADA = "S3nh@-do-GitHub"

aprovados = 0
reprovados = 0


def checar(descricao: str, condicao: bool) -> None:
    global aprovados, reprovados
    if condicao:
        aprovados += 1
        print(f"  [OK]    {descricao}")
    else:
        reprovados += 1
        print(f"  [FALHA] {descricao}")


print("\n=== Bancada de validação do cripto.py ===\n")

# --- Preparação: um sal e uma chave, derivados uma única vez ---
# (a derivação com 210 000 iterações leva ~0,2 s; não faz sentido repetir)
sal = cripto.gerar_sal()
chave = cripto.derivar_chave(SENHA_MESTRA, sal, cripto.ITERACOES_PADRAO)
chave_errada = cripto.derivar_chave("senha-que-nao-e-a-certa", sal, cripto.ITERACOES_PADRAO)

print("1. Parâmetros obrigatórios (§0.7)")
checar("sal tem 16 bytes", len(sal) == cripto.TAMANHO_SAL)
checar("chave derivada tem 32 bytes (AES-256)", len(chave) == cripto.TAMANHO_CHAVE)
checar("iterações padrão >= 210 000", cripto.ITERACOES_PADRAO >= 210_000)
checar("senhas diferentes geram chaves diferentes", chave != chave_errada)

print("\n2. Ida e volta")
aad_a = cripto.aad_segredo(COFRE_ID, SEGREDO_A)
nonce, criptograma, etiqueta = cripto.cifrar(chave, SENHA_GUARDADA, aad_a)
recuperada = cripto.decifrar(chave, nonce, criptograma, etiqueta, aad_a)
checar("a senha decifrada é igual à original", recuperada == SENHA_GUARDADA)
checar("nonce tem 12 bytes", len(cripto.de_b64(nonce)) == cripto.TAMANHO_NONCE)
checar("etiqueta tem 16 bytes", len(cripto.de_b64(etiqueta)) == 16)
checar(
    "criptograma tem o mesmo tamanho do texto claro (GCM não preenche)",
    len(cripto.de_b64(criptograma)) == len(SENHA_GUARDADA.encode("utf-8")),
)

print("\n3. Nonce novo a cada cifragem (base do Teste 1)")
n1, c1, e1 = cripto.cifrar(chave, SENHA_GUARDADA, aad_a)
n2, c2, e2 = cripto.cifrar(chave, SENHA_GUARDADA, aad_a)
checar("mesma senha, mesma chave -> nonces diferentes", n1 != n2)
checar("mesma senha, mesma chave -> criptogramas diferentes", c1 != c2)

print("\n4. Senha-mestra incorreta (base do Teste 2)")
try:
    cripto.decifrar(chave_errada, nonce, criptograma, etiqueta, aad_a)
    checar("chave errada é recusada", False)
except ValueError:
    checar("chave errada levanta ValueError e não devolve texto claro", True)

print("\n5. Registro adulterado (base do Teste 4)")
# Troca o primeiro caractere do criptograma, como o teste faz no Supabase.
adulterado = ("X" if criptograma[0] != "X" else "Y") + criptograma[1:]
try:
    cripto.decifrar(chave, nonce, adulterado, etiqueta, aad_a)
    checar("criptograma adulterado é recusado", False)
except ValueError:
    checar("criptograma adulterado levanta ValueError", True)

print("\n6. AAD amarra o criptograma ao registro (base do Teste 5)")
# Copia nonce/criptograma/etiqueta do segredo A para o segredo B, como o teste faz.
aad_b = cripto.aad_segredo(COFRE_ID, SEGREDO_B)
try:
    cripto.decifrar(chave, nonce, criptograma, etiqueta, aad_b)
    checar("criptograma movido para outro registro é recusado", False)
except ValueError:
    checar("AAD divergente levanta ValueError", True)

print("\n7. Verificador do cofre (§0.11)")
v_nonce, v_cripto, v_etiqueta = cripto.criar_verificador(chave, COFRE_ID)
checar(
    "senha-mestra correta -> True",
    cripto.senha_mestra_correta(chave, v_nonce, v_cripto, v_etiqueta, COFRE_ID) is True,
)
checar(
    "senha-mestra incorreta -> False (sem exceção vazando)",
    cripto.senha_mestra_correta(chave_errada, v_nonce, v_cripto, v_etiqueta, COFRE_ID) is False,
)
checar(
    "verificador de outro cofre -> False",
    cripto.senha_mestra_correta(chave, v_nonce, v_cripto, v_etiqueta, SEGREDO_B) is False,
)

print("\n8. O que o invasor enxerga (base do Teste 3)")
print(f"  nonce ........ {nonce}")
print(f"  criptograma .. {criptograma}")
print(f"  etiqueta ..... {etiqueta}")
checar("a senha em claro não aparece no criptograma", SENHA_GUARDADA not in criptograma)

print(f"\n=== {aprovados} aprovados, {reprovados} reprovados ===\n")
raise SystemExit(1 if reprovados else 0)
