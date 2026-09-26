# Roteiro de verificação — resultados

Os cinco testes obrigatórios (§12). Cada um confirma experimentalmente uma propriedade
da fundamentação: nonce único, verificador da senha-mestra, confidencialidade no banco,
integridade pela etiqueta e vínculo ao contexto pelo AAD.

## Como foram executados

Foi criado um cofre novo só para os testes, com três segredos guardando a **mesma senha**,
e os cinco testes foram executados em sequência contra a API e o Supabase reais. As ações
do invasor (consultar e adulterar a tabela) foram feitas direto no banco com a chave
pública, sem passar pela API — o mesmo acesso que a política `laboratorio` concede a
qualquer portador dela.

| Arquivo | Conteúdo |
|---|---|
| `evidencias/teste_0.txt` | Preparação: criação do cofre e dos segredos, leitura de controle, listagem |
| `evidencias/teste_1.txt` … `teste_5.txt` | Saída de cada teste |

**Cofre usado:** `6fed8974-0e1f-46e7-8699-e336af0de624` · **Data da execução:** 26/09/2026 · **Resultado:** 18 verificações aprovadas, 0 reprovadas

---

## Teste 1 — Nonces distintos

**Procedimento:** cadastrar duas vezes a mesma senha, com títulos diferentes, no mesmo cofre,
e consultar a tabela `segredos`.

**Esperado:** `nonce` e `criptograma` diferentes nos dois registros.

**Observado:** os dois registros guardam a mesma senha (`S3nh@-Repetida-123`), mas os nonces (`xwFw2lW8mp/QXach` × `IbiToyhUN9q+RGHc`), os criptogramas (`2XkKntRwpgZ1o3Ll3ZBtBB0b` × `6HTGZXY6wKJebskhCc3oq14O`) e as etiquetas saíram todos diferentes. **Passou.**

**Conclusão:** o nonce é sorteado a cada cifragem (`get_random_bytes(12)` dentro de
`cifrar()`), então a mesma senha com a mesma chave gera criptogramas distintos. Quem lê o
banco não consegue sequer saber que dois registros protegem a mesma senha.

**Evidência:** `evidencias/teste_1.txt`

## Teste 2 — Senha-mestra incorreta

**Procedimento:** pedir a leitura de um segredo com uma senha-mestra errada no cabeçalho
`X-Senha-Mestra`.

**Esperado:** **401**, sem conteúdo do segredo no corpo.

**Observado:** `401 {"detail":"Senha-mestra incorreta"}` — o corpo não contém nada do segredo. **Passou.**

**Conclusão:** a chave derivada da senha errada não abre o verificador `cofre-ok`; a API
responde 401 antes de tocar no segredo.

**Evidência:** `evidencias/teste_2.txt`

## Teste 3 — O que o invasor enxerga

**Procedimento:** consulta direta no Supabase:

```sql
select titulo, usuario, nonce, criptograma, etiqueta
from public.segredos;
```

**Esperado:** nenhuma senha legível, apenas Base64 sem significado aparente.

**Observado:** os três registros mostram título e usuário em claro e, nas colunas `nonce`, `criptograma` e `etiqueta`, apenas Base64 (ex.: `2XkKntRwpgZ1o3Ll3ZBtBB0b`). A senha não aparece em nenhum campo. **Passou.**

**Conclusão:** o banco só guarda criptogramas. Título e usuário aparecem em claro, por
decisão de projeto — ver limitações no README.

**Evidência:** `evidencias/teste_3.txt`

## Teste 4 — Registro adulterado

**Procedimento:** trocar o primeiro caractere do `criptograma` e ler pela API com a
senha-mestra **correta**:

```sql
update public.segredos
set criptograma = 'X' || substring(criptograma from 2)
where id = '<id do segredo>';
```

**Esperado:** **500** indicando adulteração, sem texto claro, com o `ValueError` tratado.

**Observado:** criptograma alterado de `2XkKntRwpgZ1o3Ll3ZBtBB0b` para `XXkKntRwpgZ1o3Ll3ZBtBB0b`; a leitura com a senha-mestra correta devolveu `500 {"detail":"Falha de integridade: registro adulterado"}`, sem texto claro e sem traceback. **Passou.**

**Conclusão:** o verificador passa (a senha-mestra está certa), mas a etiqueta do segredo
não confere. O GCM aborta antes de devolver qualquer byte de texto claro, e a API converte
o `ValueError` em 500 com mensagem própria, sem traceback.

**Evidência:** `evidencias/teste_4.txt`

## Teste 5 — Troca de criptogramas entre registros

**Procedimento:** copiar `nonce`, `criptograma` e `etiqueta` de um segredo para outro do
mesmo cofre e ler o segredo de destino.

**Esperado:** leitura recusada.

**Observado:** com os três campos copiados, o registro de origem continuou legível (200), e o de destino devolveu `500 {"detail":"Falha de integridade: registro adulterado"}`, sem texto claro. **Passou.**

**Conclusão:** os três campos copiados são um criptograma válido, produzido com a chave
certa — mas o AAD é `cofre_id|segredo_id`, e o id do destino difere do de origem. A
etiqueta não confere e a leitura é recusada. Sem AAD, a API decifraria normalmente e
mostraria a senha de um sistema no lugar da de outro.

**Evidência:** `evidencias/teste_5.txt`

---

## Resumo

| Teste | Esperado | Observado |
|---|---|---|
| 1 — Nonces distintos | nonces e criptogramas diferentes | nonces, criptogramas e etiquetas diferentes ✅ |
| 2 — Senha-mestra incorreta | 401, sem conteúdo | 401, sem conteúdo ✅ |
| 3 — O que o invasor enxerga | apenas Base64 | apenas Base64 ✅ |
| 4 — Registro adulterado | 500, sem texto claro | 500, sem texto claro ✅ |
| 5 — Troca de criptogramas | leitura recusada | 500 no destino; origem segue legível (200) ✅ |
