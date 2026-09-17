# Divisão de tarefas — Cofre de Senhas AES-GCM

**PUC Goiás · Ciência da Computação / Engenharia de Computação · Criptografia Aplicada**
**Módulo 3 — Criptografia Simétrica · Projeto de Laboratório**

Equipe: **João Marcelo** e **Saddi**

Tecnologias: Python 3.10+ · FastAPI · PyCryptodome · PostgreSQL (Supabase)

Entrega: repositório público no GitHub

Senha do Supabase: REMOVIDO

## API's supabase:
---
url: syjowndvwxyjmfivbdqe

api url: https://syjowndvwxyjmfivbdqe.supabase.co/rest/v1/

public api: REMOVIDO

anon public: REMOVIDO

## Como ler este arquivo

Cobre **todo** o enunciado `Projeto_Cofre_AES.docx`. As referências `§N` apontam para a seção
original, caso alguém queira a explicação longa.

- **Parte 0** — referência comum: o que os dois precisam saber antes de começar
- **Parte 1** — João Marcelo
- **Parte 2** — Saddi
- **Parte 3** — trabalho conjunto: ambiente, ordem de execução e entrega
- **Parte 4** — regras invioláveis
- **Parte 5** — apêndices: testes detalhados, erros comuns, glossário, referências

---

## A divisão em uma tabela

Segue exatamente os cinco critérios de avaliação (§15). Cada critério tem um dono único,
e ninguém encosta no arquivo do outro.

| Critério de avaliação | O que se avalia | Dono | Pontos |
|---|---|---|---:|
| Implementação criptográfica | PBKDF2 com os parâmetros exigidos; GCM com nonce único por operação; AAD correto nos dois sentidos | João Marcelo | 3,0 |
| Roteiro de verificação | Os cinco testes executados, com evidências e resultados registrados | João Marcelo | 2,0 |
| API | Rotas completas, códigos de resposta corretos, senha-mestra em cabeçalho, tratamento de exceções | Saddi | 2,5 |
| Banco de dados | Esquema conforme especificado, integração funcional, listagem sem exposição de campos sensíveis | Saddi | 1,5 |
| Repositório e documentação | Estrutura, README completo, ausência de credenciais versionadas | Saddi | 1,0 |
| **Total** | | | **10,0** |

> `cripto.py` é o arquivo mais curto e o mais difícil — umas oitenta linhas onde um parâmetro
> esquecido derruba três pontos. `main.py` é o inverso: longo, repetitivo e de baixo risco.
> 5,0 e 5,0 não significam o mesmo número de linhas digitadas.

---
---

# PARTE 0 — Referência comum

## 0.1 Regras do trabalho e da entrega (§1.2)

- Equipes de **até três** integrantes. A nossa tem dois.
- **Cada equipe cria a própria conta e o próprio projeto no Supabase.** É proibido reaproveitar
  bancos existentes ou compartilhar um mesmo banco entre equipes.
- A entrega é o **endereço de um repositório público no GitHub**, enviado pelo canal indicado
  em aula, dentro do prazo estabelecido.
- **Não há notebook a preencher, questões discursivas nem desafio final.** A avaliação recai
  integralmente sobre o código entregue e sobre as evidências de que ele funciona.

## 0.2 Objetivos de aprendizagem (§1.1)

O que o professor espera que a entrega demonstre — serve de guia para o que escrever no README:

- Aplicar o AES em modo GCM para proteger dados persistidos, distinguindo confidencialidade de integridade
- Justificar o uso de uma função de derivação de chave e configurar seus parâmetros
- Manipular corretamente nonce, etiqueta de autenticação e dados associados em um sistema real
- Identificar quais informações podem ser persistidas e quais jamais devem ser
- Demonstrar experimentalmente que as garantias da cifra autenticada se sustentam sob adulteração

## 0.3 Por que cifrar na aplicação (§2.1, §2.2)

Contexto que precisa aparecer no README:

- O cenário-problema: credenciais compartilhadas em texto claro num banco. Quem obtém acesso ao
  banco não precisa atacar nada — basta executar uma consulta.
- **A criptografia de disco do provedor não resolve este caso.** Ela protege apenas contra roubo
  físico do disco. O banco, ao receber uma consulta legítima, devolve os dados já decifrados —
  para o invasor autenticado ou com cópia lógica, a criptografia de disco é invisível.
- A proteção necessária é a **cifragem no nível da aplicação**: o dado é cifrado antes de sair do
  programa e só é decifrado ao voltar. O banco nunca vê o texto claro e nunca possui a chave.

## 0.4 Modelo de ameaças (§2.3) — vai no README

| Situação | O cofre protege? |
|---|---|
| Cópia integral do banco de dados obtida por um invasor | **Sim.** Apenas criptogramas são armazenados |
| Consulta SQL direta às tabelas por pessoa não autorizada | **Sim.** O resultado é texto codificado, sem utilidade |
| Alteração maliciosa de um registro no banco | **Sim.** A etiqueta de autenticação rejeita o dado adulterado |
| Servidor de aplicação comprometido durante o uso | **Não.** A senha-mestra passa pela memória do servidor |
| Senha-mestra fraca ou divulgada pela equipe | **Não.** A segurança do cofre é a segurança dessa senha |
| Registro do que cada usuário acessou e quando | **Não.** Auditoria está fora do escopo |

> As duas últimas linhas **não são defeitos a corrigir** — são limites deliberados de escopo.
> O README deve declará-las. Reconhecer o que o sistema não faz é tão importante quanto
> demonstrar o que ele faz.

## 0.5 Fundamentação do PBKDF2 (§3) — vai no README

- **Por que não usar a senha como chave (§3.1):** o AES-256 exige 32 bytes imprevisíveis. Uma senha
  humana erra o comprimento *e* a distribuição — caracteres imprimíveis, estrutura reconhecível,
  conjunto muito menor que os 256 valores de um byte. Completar com zeros resolveria o tamanho e
  nada do que importa.
- **O sal (§3.2):** bytes aleatórios, gerados **uma vez por cofre** e guardados **em texto claro**.
  Não é secreto. Garante que duas equipes com a mesma senha-mestra não produzam a mesma chave.
  Sem ele, um invasor calcularia uma vez as chaves das senhas comuns e testaria contra todos os
  cofres simultaneamente; com sal distinto, cada cofre precisa ser atacado do zero.
- **As iterações (§3.3):** tornam o cálculo deliberadamente lento. A lógica é assimétrica e favorece
  o defensor — o usuário legítimo paga o atraso uma vez por sessão, o atacante paga em cada uma
  das milhões de tentativas.

| Iterações | Tempo por tentativa | Senhas testadas por segundo |
|---:|---|---:|
| 1 | ~1 microssegundo | ~1 000 000 |
| 10 000 | ~0,01 segundo | ~100 |
| 210 000 | ~0,2 segundo | ~5 |

- **Por que guardar o número de iterações no banco:** o valor recomendado cresce com o tempo.
  Guardar o usado em cada cofre permite abrir cofres antigos depois que o padrão for elevado.

## 0.6 Fundamentação do AES-GCM (§4) — vai no README

- **As três saídas (§4.1):** cada cifragem devolve **nonce** (12 bytes, não secreto),
  **criptograma** (mesmo comprimento do texto claro — o GCM opera como cifra de fluxo, sem
  preenchimento) e **etiqueta de autenticação** (16 bytes, não secreta). Os três são armazenados.
  Os 28 bytes extras por registro são o nonce e a etiqueta.
- **A regra do nonce (§4.2):** garante que a mesma senha, com a mesma chave, produza criptogramas
  diferentes a cada vez — o invasor não consegue nem saber se duas entradas protegem a mesma senha.
  **Repetir um nonce com a mesma chave é a falha mais grave possível no GCM:** permite recuperar o
  texto claro por cancelamento do fluxo de chave e compromete a detecção de adulterações.
  Regra prática: `get_random_bytes(12)` imediatamente antes de cada cifragem, sem exceção.
- **A etiqueta (§4.3):** ao decifrar, o GCM recalcula a etiqueta e compara. Qualquer divergência
  aborta a operação e **nenhum byte de texto claro é devolvido** — a verificação ocorre antes da
  entrega, não depois. A biblioteca lança `ValueError: MAC check failed`. Isso é o comportamento
  correto: a alternativa seria devolver lixo que a aplicação trataria como senha verdadeira.
- **Dados associados / AAD (§4.4):** não é cifrado, permanece legível no banco, mas entra no cálculo
  da etiqueta — amarra o criptograma a um contexto. Resolve o ataque do invasor com acesso de
  escrita que copia o criptograma de produção para o registro de testes: sem AAD a aplicação
  decifraria normalmente e exibiria a senha errada no lugar certo.

## 0.7 Parâmetros obrigatórios — valores fechados (§3.4, §4.1, §13.1)

| Parâmetro | Valor | Onde vive |
|---|---|---|
| Função de derivação | PBKDF2 com **HMAC-SHA-256** | `cripto.py` |
| Tamanho da chave derivada | **32 bytes** (AES-256) | `cripto.py` |
| Sal | **16 bytes** aleatórios, um por cofre, guardado em claro | `cripto.py` + coluna `kdf_sal` |
| Iterações | **no mínimo 210 000**, registradas no banco | `cripto.py` + coluna `kdf_iteracoes` |
| Modo do AES | **GCM** (nunca ECB, nunca CBC) | `cripto.py` |
| Nonce | **12 bytes** aleatórios, novo a cada cifragem | `cripto.py` + coluna `nonce` |
| Etiqueta | **16 bytes** | coluna `etiqueta` |
| Frase verificadora | `cofre-ok` | `cripto.py` |
| Codificação no banco | Base64 em colunas `text` | `cripto.py` (`para_b64` / `de_b64`) |

## 0.8 Contrato de interface (§9)

Assinaturas **obrigatórias** — os testes da Etapa 6 dependem delas. São também o que permite
trabalhar em paralelo: o Saddi escreve `main.py` chamando funções que ainda não existem,
confiando no contrato. **Ninguém muda uma assinatura sem avisar o outro.**

```python
# app/cripto.py — dono: João Marcelo

import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

ITERACOES_PADRAO = 210_000
TAMANHO_CHAVE    = 32   # bytes, AES-256
TAMANHO_SAL      = 16   # bytes
TAMANHO_NONCE    = 12   # bytes, valor recomendado para o GCM

FRASE_VERIFICADORA = "cofre-ok"

# --- auxiliares de codificação (prontos no enunciado) ---
para_b64(dados: bytes) -> str      # base64.b64encode(dados).decode("ascii")
de_b64(texto: str) -> bytes        # base64.b64decode(texto)

# --- as quatro funções a implementar ---
derivar_chave(senha_mestra: str, sal: bytes, iteracoes: int) -> bytes
gerar_sal() -> bytes
cifrar(chave: bytes, texto_claro: str, aad: bytes) -> tuple[str, str, str]
decifrar(chave: bytes, nonce_b64: str, cripto_b64: str,
         etiqueta_b64: str, aad: bytes) -> str

# --- verificador do cofre ---
criar_verificador(chave: bytes, cofre_id: str) -> tuple[str, str, str]
senha_mestra_correta(chave, nonce, cripto, etiqueta, cofre_id) -> bool
```

**Regras do contrato:**

- `cifrar()` devolve `(nonce, criptograma, etiqueta)` nessa ordem, os três já em Base64
- `decifrar()` **não captura o `ValueError`** — deixa subir, para que o `main.py` decida a resposta HTTP
- `senha_mestra_correta()` captura o `ValueError` internamente e devolve `True` / `False`

**Montagem do AAD — precisa ser idêntica na cifragem e na decifragem:**

```python
aad_verificador = cofre_id.encode()                    # só o id do cofre
aad_segredo     = f"{cofre_id}|{segredo_id}".encode()  # cofre + segredo

# exemplo:
# 3f2b8c10-9e44-4d0b-8a71-6c5d2e0f4a19|b1d7e2a4-05c8-4f39-9b62-77ae3c1d80f5
```

> Escrever **uma função auxiliar única** para montar o AAD dos segredos e usá-la nos dois sentidos.
> AAD divergente é o erro nº 1 da lista de erros comuns do enunciado.

## 0.9 Fluxo de gravação (§5.1) — especificação do `main.py`

Ordem exata a seguir quando um usuário cadastra uma credencial:

1. A **senha-mestra chega no cabeçalho** da requisição, junto com o título do segredo e a senha a proteger
2. A API busca no banco o **sal** e o **número de iterações** do cofre indicado
3. A **chave de 32 bytes é derivada** com PBKDF2 a partir da senha-mestra, do sal e das iterações
4. A senha-mestra é **verificada contra o verificador** do cofre (§0.11)
5. Um **identificador é gerado** para o novo segredo e um **nonce de 12 bytes é sorteado**
6. A senha é **cifrada com AES-GCM**, usando a chave, o nonce e o AAD do registro
7. **Nonce, criptograma e etiqueta são gravados** no banco em Base64. A chave e a senha-mestra são
   **descartadas ao término da requisição**

## 0.10 Fluxo de leitura (§5.2) — especificação do `main.py`

O caminho inverso:

1. A chave é **derivada novamente** a partir da senha-mestra recebida
2. Os três campos são **lidos do banco e decodificados** de Base64
3. A decifragem é feita **com verificação da etiqueta**
4. Se a verificação falhar, a API responde com erro e **não devolve conteúdo algum**

## 0.11 O verificador do cofre (§5.3)

O problema: senha-mestra incorreta e registro adulterado produzem **a mesma exceção**. A solução
é o verificador, também chamado canário.

Na criação do cofre, a API cifra a cadeia fixa `cofre-ok` com a chave derivada e guarda o resultado
no próprio registro do cofre. **Toda requisição posterior tenta primeiro decifrar esse verificador:**

| Resultado | Significado | Resposta |
|---|---|---|
| Verificador **falha** | Senha-mestra incorreta | **401** |
| Verificador **passa**, mas o segredo falha | Chave correta, registro adulterado | **500** |

> O verificador não armazena a senha-mestra nem derivação reversível dela — apenas o resultado de
> uma cifragem que só pode ser reproduzida por quem conhece a senha correta.

## 0.12 O que é e o que não é armazenado (§5.4)

| Armazenado no banco | **Nunca** armazenado |
|---|---|
| Sal e número de iterações | Senha-mestra, em qualquer forma |
| Nonce, criptograma e etiqueta | Chave derivada |
| Verificador do cofre | Senhas em texto claro |
| Título, usuário e URL do segredo | Registro de senhas digitadas |

> Título, usuário e URL ficam em **texto claro** por decisão de projeto, para permitir a listagem
> sem a senha-mestra. Tem custo: quem obtiver o banco saberá quais sistemas a equipe acessa, ainda
> que não conheça as senhas. **Essa consequência deve ser discutida no README.**

## 0.13 As quatro camadas (§6)

A separação é **obrigatória** — a lógica criptográfica não pode estar misturada com o tratamento
das requisições nem com o acesso ao banco.

| Arquivo | Responsabilidade | Dono |
|---|---|---|
| `app/cripto.py` | Derivação de chave, cifragem e decifragem. **Não conhece HTTP nem banco** | João |
| `app/banco.py` | Leitura e escrita no Supabase. **Não conhece criptografia** | Saddi |
| `app/modelos.py` | Formato dos dados que entram e saem da API | Saddi |
| `app/main.py` | Rotas, códigos de resposta e orquestração das duas camadas | Saddi |

---
---

# PARTE 1 — João Marcelo · 5,0 pontos

Tudo que envolve a criptografia em si e a prova experimental de que ela funciona.
**Não encosta em `banco.py`, `main.py` nem no README** (entrega trechos, o Saddi consolida).

## Frente A — Módulo de criptografia (3,0 pts) · §9

Arquivos: `app/cripto.py` · `app/__init__.py`

**Preparação**

- [ ] Criar a pasta `app/` e dentro dela o `__init__.py` **vazio** — sua presença indica ao Python que a pasta é um pacote
- [ ] Transcrever as importações e as constantes de §0.7 / §0.8
- [ ] Transcrever `para_b64` e `de_b64` — já vêm prontos no enunciado (§9.2)

**`derivar_chave(senha_mestra, sal, iteracoes) -> bytes`** (§9.3)

- [ ] Chamar `PBKDF2` passando, **nesta ordem**, a senha-mestra e o sal
- [ ] `dkLen=TAMANHO_CHAVE` para obter 32 bytes
- [ ] `count=iteracoes`
- [ ] **`hmac_hash_module=SHA256`** — sem esse parâmetro a biblioteca usa **SHA-1** por padrão, o que não é aceitável
- [ ] Devolver o resultado, que já é `bytes`

**`gerar_sal() -> bytes`**

- [ ] Uma linha: `return get_random_bytes(TAMANHO_SAL)`

**`cifrar(chave, texto_claro, aad) -> (nonce, criptograma, etiqueta)`**

- [ ] Sortear o nonce com `get_random_bytes(TAMANHO_NONCE)`
- [ ] Criar a cifra com `AES.new(chave, AES.MODE_GCM, nonce=nonce)`
- [ ] Registrar os dados associados com `cifra.update(aad)` — **esta chamada precisa vir antes da cifragem**
- [ ] Converter o texto claro com `texto_claro.encode("utf-8")`
- [ ] Obter criptograma e etiqueta **de uma só vez** com `cifra.encrypt_and_digest(...)`
- [ ] Devolver os três valores convertidos com `para_b64`

**`decifrar(chave, nonce_b64, cripto_b64, etiqueta_b64, aad) -> str`**

- [ ] Converter os três parâmetros Base64 de volta para bytes com `de_b64`
- [ ] Criar a cifra com `AES.new(chave, AES.MODE_GCM, nonce=nonce)` — **o mesmo nonce da cifragem**
- [ ] Chamar `cifra.update(aad)` com **exatamente o mesmo AAD** da cifragem
- [ ] Chamar `cifra.decrypt_and_verify(criptograma, etiqueta)`
- [ ] **Não capturar a exceção aqui** — deixar o `ValueError` subir para a camada da API
- [ ] Devolver o resultado com `.decode("utf-8")`

**Verificador do cofre** (§9.4)

- [ ] `criar_verificador(chave, cofre_id)` — chama `cifrar()` com `aad = cofre_id.encode()` sobre `FRASE_VERIFICADORA`
- [ ] `senha_mestra_correta(...)` — chama `decifrar()` dentro de `try/except ValueError`; devolve `True` se o texto obtido for igual a `FRASE_VERIFICADORA`, `False` se ocorrer `ValueError`
- [ ] Função auxiliar única para montar o AAD dos segredos (§0.8), usada na cifragem e na decifragem

**Validação antes da integração**

- [ ] Bancada de testes: script solto que cifra e decifra **sem HTTP e sem Supabase**, para não ficar
      parado esperando a API do Saddi e chegar na Etapa 6 com o módulo já confiável

## Frente B — Roteiro de verificação (2,0 pts) · §12

Arquivos: `testes/resultados.md` · `testes/evidencias/`

Os cinco testes são **obrigatórios**. Cada um confirma experimentalmente uma propriedade da Parte I.
As evidências — capturas de tela ou saídas de terminal — vão em `testes/evidencias/`, e o resultado
observado em cada um vai escrito em `testes/resultados.md`. Detalhamento completo no **Apêndice A**
deste arquivo.

- [ ] **Teste 1 — Nonces distintos**
- [ ] **Teste 2 — Senha-mestra incorreta**
- [ ] **Teste 3 — O que o invasor enxerga**
- [ ] **Teste 4 — Registro adulterado**
- [ ] **Teste 5 — Troca de criptogramas entre registros**
- [ ] Capturas de tela de cada um em `testes/evidencias/`
- [ ] `testes/resultados.md` com os cinco testes e o que se observou

> **Dependência:** os cinco testes só rodam com a API de pé e o banco populado. São a última etapa
> do cronograma — por isso as frentes A e B não são consecutivas, e a bancada de validação
> preenche o meio.

## Frente C — Contribuição ao README (apoio) · §14.2

Trechos entregues ao Saddi, que consolida o arquivo.

- [ ] **Justificativa dos parâmetros criptográficos:** por que PBKDF2, por que 210 000 iterações,
      por que sal de 16 bytes, por que nonce de 12 bytes, por que guardar o número de iterações no
      banco, por que GCM em vez de ECB ou CBC — matéria de §0.5, §0.6 e §0.7
- [ ] **Declaração das limitações:** as duas últimas linhas do modelo de ameaças (§0.4) e o custo de
      deixar título, usuário e URL em texto claro (§0.12)

---
---

# PARTE 2 — Saddi · 5,0 pontos

A aplicação em volta do núcleo: banco, rotas e entrega.
**Não encosta em `cripto.py` nem na pasta `testes/`.**

## Frente A — Banco de dados (1,5 pts) · §8, §10

Arquivos: `sql/esquema.sql` · `app/banco.py` · `.env` (local) · `.env.exemplo` (versionado)

**Criação do projeto no Supabase** (§8.1)

- [ ] Criar conta em `supabase.com` (dá para autenticar com o GitHub, o que simplifica)
- [ ] Criar um novo projeto — nome sugerido `cofre-aes-equipeNN`
- [ ] Definir a senha do banco. **É a do administrador do PostgreSQL, não a senha-mestra do cofre.**
      Guardar, embora não seja usada diretamente pela API
- [ ] Escolher a região mais próxima — **South America (São Paulo)**
- [ ] Aguardar a criação (leva alguns minutos)

**Tabelas** (§8.2) — SQL Editor → New query → Run, e salvar em `sql/esquema.sql`

```sql
create table public.cofres (
  id                       uuid primary key,
  nome                     text        not null,
  kdf_sal                  text        not null,
  kdf_iteracoes            integer     not null,
  verificador_nonce        text        not null,
  verificador_criptograma  text        not null,
  verificador_etiqueta     text        not null,
  criado_em                timestamptz not null default now()
);

create table public.segredos (
  id            uuid primary key,
  cofre_id      uuid        not null,
  titulo        text        not null,
  usuario       text,
  url           text,
  nonce         text        not null,
  criptograma   text        not null,
  etiqueta      text        not null,
  criado_em     timestamptz not null default now(),
  atualizado_em timestamptz not null default now(),
  foreign key (cofre_id) references public.cofres(id)
    on delete cascade
);

create index idx_segredos_cofre on public.segredos (cofre_id);
```

- [ ] Rodar o script acima
- [ ] Entender por que `nonce`, `criptograma` e `etiqueta` são `text`: armazenam bytes em **Base64**,
      representação que permite transportá-los em texto e em JSON sem corrupção
- [ ] Lembrar da coluna `atualizado_em` — o `PUT` precisa atualizá-la

**Políticas de acesso** (§8.3)

```sql
alter table public.cofres   enable row level security;
alter table public.segredos enable row level security;

create policy "laboratorio" on public.cofres
  for all to anon using (true) with check (true);

create policy "laboratorio" on public.segredos
  for all to anon using (true) with check (true);
```

- [ ] Rodar o script e conferir que as **duas** tabelas receberam política
      (aplicar em só uma causa o erro `new row violates row-level security policy`)

> **A permissão ampla é intencional.** Ela libera leitura e escrita a qualquer portador da chave
> pública e serve ao propósito didático: simula precisamente o invasor que obteve cópia do banco.
> Em produção, essas tabelas seriam acessadas só pelo servidor, com credenciais restritas — mas a
> proteção do conteúdo continuaria vindo da cifragem, não da política de acesso.

**Credenciais** (§8.4)

- [ ] Project Settings → seção de chaves da API. Pegar a **URL do projeto** (`https://xxxxxxxx.supabase.co`)
      e a **chave pública** (`anon` / `publishable`)
- [ ] Criar o `.env` na raiz — **nunca versionado**:

```
SUPABASE_URL=https://xxxxxxxx.supabase.co
SUPABASE_KEY=eyJhbGciOi...
```

- [ ] Criar o `.env.exemplo` com os **mesmos nomes de variáveis e valores fictícios** — este é
      versionado normalmente: documenta a configuração sem expor segredo algum

**Conexão** (§10.1)

```python
import os
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()          # lê o arquivo .env

supabase: Client = create_client(
    os.environ["SUPABASE_URL"],
    os.environ["SUPABASE_KEY"],
)
```

**Funções nomeadas** (§10.2) — o `main.py` **não pode conter chamadas diretas ao Supabase**

- [ ] `inserir_cofre` · `buscar_cofre`
- [ ] `inserir_segredo` · `listar_segredos` · `buscar_segredo` · `atualizar_segredo` · `remover_segredo`

Os quatro padrões do cliente (encadeamento sempre terminado em `.execute()`):

```python
# inserir um registro
supabase.table("cofres").insert({...}).execute()

# buscar um registro por identificador
consulta  = supabase.table("cofres").select("*").eq("id", cofre_id)
resposta  = consulta.execute()
registros = resposta.data          # lista de dicionários
cofre     = registros[0] if registros else None

# listar registros filtrando por uma coluna
resposta = supabase.table("segredos").select(
    "id, titulo, usuario, url, criado_em"
).eq("cofre_id", cofre_id).execute()

# remover um registro
supabase.table("segredos").delete().eq("id", segredo_id).execute()
```

- [ ] **Em `listar_segredos`, jamais usar `select("*")`** — nomear explicitamente as colunas de
      metadados. A rota de listagem **não pode devolver** `nonce`, `criptograma` nem `etiqueta`.
      Reduzir a exposição ao mínimo necessário é item de avaliação

## Frente B — A API (2,5 pts) · §11

Arquivos: `app/modelos.py` · `app/main.py`

**Modelos Pydantic** (§11.1) — o FastAPI valida e responde **422** quando o formato não corresponde

```python
from pydantic import BaseModel

class NovoCofre(BaseModel):
    nome: str
    senha_mestra: str

class NovoSegredo(BaseModel):
    titulo: str
    usuario: str | None = None
    url: str | None = None
    senha: str
```

**As sete rotas obrigatórias** (§11.2)

| Método e rota | Comportamento |
|---|---|
| `POST /cofres` | Cria o cofre: gera sal, deriva a chave, monta o verificador e grava. **201** com o id do cofre |
| `POST /cofres/{id}/abrir` | Confere a senha-mestra contra o verificador. **200** ou **401** |
| `POST /cofres/{id}/segredos` | Cifra e grava uma credencial. **201** com o id do segredo |
| `GET /cofres/{id}/segredos` | Lista os metadados dos segredos. **Nunca devolve senhas** |
| `GET /cofres/{id}/segredos/{sid}` | Decifra e devolve a senha solicitada |
| `PUT /cofres/{id}/segredos/{sid}` | Substitui a senha, **obrigatoriamente com um novo nonce** |
| `DELETE /cofres/{id}/segredos/{sid}` | Remove o registro |

- [ ] As sete rotas implementadas, seguindo os fluxos de §0.9 e §0.10
- [ ] Verificador conferido **antes** de tocar no segredo, em toda rota que exige senha-mestra
- [ ] No `PUT`, **gerar nonce novo** e atualizar `atualizado_em`
- [ ] Chave e senha-mestra **descartadas ao fim de cada requisição** — nada de cache entre chamadas

**A senha-mestra no cabeçalho** (§11.3)

Com exceção da criação do cofre, **todas** as rotas exigem a senha-mestra no cabeçalho
`X-Senha-Mestra`. A conversão do nome é automática: o parâmetro `x_senha_mestra` corresponde ao
cabeçalho `X-Senha-Mestra`.

```python
from fastapi import FastAPI, Header, HTTPException

app = FastAPI(title="Cofre de Senhas")

@app.get("/cofres/{cofre_id}/segredos/{segredo_id}")
def ler_segredo(cofre_id: str, segredo_id: str,
                x_senha_mestra: str = Header(...)):
    ...
```

- [ ] `Header(...)` em todas as rotas que exigem a senha-mestra

> O uso de cabeçalho, em vez do corpo ou da URL, evita que a senha-mestra apareça em registros
> de servidor e no histórico do navegador.

**Códigos de resposta** (§11.4) — **a distinção entre eles é parte da avaliação**

| Código | Quando utilizar |
|---|---|
| **200** | Operação de leitura ou atualização bem-sucedida |
| **201** | Cofre ou segredo criado |
| **401** | Verificador falhou: a senha-mestra está incorreta |
| **404** | O cofre ou o segredo indicado não existe |
| **422** | Formato da requisição inválido — gerado automaticamente pelo FastAPI |
| **500** | Verificador aprovado, mas um segredo falhou na etiqueta: registro adulterado |

```python
raise HTTPException(status_code=401, detail="senha-mestra incorreta")
```

- [ ] Os seis códigos usados corretamente
- [ ] **Tratamento explícito do `ValueError`** vindo do `cripto.py`, convertido em resposta HTTP —
      nunca um traceback vazando para o cliente

**Execução e teste manual** (§11.5)

```bash
uvicorn app.main:app --reload
```

- [ ] Servidor sobe a partir da raiz do projeto com o ambiente virtual ativo
- [ ] `http://127.0.0.1:8000/docs` abre a interface interativa gerada pelo FastAPI —
      todas as rotas testáveis com **Try it out**, incluindo o preenchimento do cabeçalho.
      **Não é necessário programar um cliente para testar**

> `app.main:app` indica o objeto `app` definido em `app/main.py`. O `--reload` reinicia o servidor
> a cada alteração e **deve ser usado apenas em desenvolvimento**.

## Frente C — Repositório e documentação (1,0 pt) · §14

Arquivos: `README.md` · `.gitignore` · `requirements.txt`

- [ ] **`.gitignore` criado antes do primeiro envio** (conteúdo em §3.1 da Parte 3)
- [ ] `requirements.txt` gerado com `pip freeze > requirements.txt`, com as versões reais instaladas
- [ ] Estrutura de pastas exatamente como a árvore de §3.4 da Parte 3
- [ ] Repositório **público** no GitHub, criado **sem arquivo inicial algum**

**README com as cinco seções obrigatórias** (§14.2)

- [ ] Identificação da equipe e dos integrantes
- [ ] Instruções de instalação e execução, permitindo que **um terceiro reproduza o ambiente**
- [ ] Descrição das rotas disponíveis, **com um exemplo de requisição e de resposta**
- [ ] Justificativa dos parâmetros criptográficos adotados *(texto do João — Frente C)*
- [ ] Declaração das limitações do sistema, conforme §0.4 e §0.12 *(texto do João — Frente C)*

---
---

# PARTE 3 — Trabalho conjunto

## 3.1 Fase 0 — Preparação do ambiente (§7) · os dois, numa sentada só

**Verificação do Python** (§7.1)

```bash
python --version
```

- [ ] Resposta deve indicar **3.10 ou superior**. Em algumas distribuições Linux e no macOS o comando
      é `python3` — nesse caso, usar `python3` em todos os comandos. Abaixo de 3.10 ou comando não
      reconhecido: instalar a partir de `python.org` antes de prosseguir

**Pasta e ambiente virtual** (§7.2)

```bash
mkdir cofre-aes
cd cofre-aes
python -m venv .venv
```

Ativação — difere entre sistemas:

| Sistema | Comando de ativação |
|---|---|
| Windows (PowerShell) | `.venv\Scripts\Activate.ps1` |
| Windows (Prompt de Comando) | `.venv\Scripts\activate.bat` |
| Linux e macOS | `source .venv/bin/activate` |

- [ ] Após a ativação o terminal exibe `(.venv)` no início da linha. **Precisa estar ativo sempre
      que o projeto for executado** — ao abrir um novo terminal, repetir a ativação

> **Se o PowerShell recusar a execução:** o Windows bloqueia scripts por padrão. Rodar uma única
> vez, no mesmo terminal, e responder `S`:
> ```powershell
> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
> ```

**Instalação das bibliotecas** (§7.3)

```bash
pip install fastapi "uvicorn[standard]" pycryptodome
pip install supabase python-dotenv
```

| Biblioteca | Função no projeto |
|---|---|
| `fastapi` | Construção da API: rotas, validação e documentação automática |
| `uvicorn` | Servidor que executa a aplicação e responde às requisições |
| `pycryptodome` | Implementação do AES-GCM e do PBKDF2. É a mesma biblioteca do Módulo 3 |
| `supabase` | Cliente de acesso ao banco PostgreSQL |
| `python-dotenv` | Leitura das credenciais a partir de um arquivo externo ao código |

> O pacote **se instala como `pycryptodome` e se importa como `Crypto`**.

**`.gitignore` — antes de qualquer commit** (§8.4)

```
.venv/
.env
__pycache__/
```

- [ ] Criado **antes** do primeiro envio ao GitHub. Credenciais publicadas em repositórios públicos
      são localizadas por varredura automatizada **em questão de minutos**

**Fechamento da Fase 0**

- [ ] Esqueleto dos quatro arquivos de `app/` criado com as assinaturas de §0.8 e `pass` no corpo
- [ ] `git init` e primeiro commit com o esqueleto — a partir daqui, cada um mexe só nos seus arquivos

## 3.2 Ordem de execução

A numeração é real: cada fase depende da anterior ter terminado. Dentro de uma fase, as duas
faixas correm ao mesmo tempo.

| Fase | João Marcelo | Saddi |
|---|---|---|
| **0 — Fundação** *(juntos)* | Python, venv, bibliotecas, `.gitignore`, esqueleto dos quatro arquivos, `git init`, primeiro commit | *(idem — sentados juntos)* |
| **1 — Cada um no seu canto** | `cripto.py` inteiro: as seis funções | Supabase de pé, `esquema.sql`, `banco.py`, `modelos.py` |
| **2 — Enquanto a API nasce** | Bancada de validação do `cripto.py` + trechos criptográficos do README | `main.py`: sete rotas, cabeçalho, códigos de resposta |
| **3 — Integração** *(juntos)* | Primeira chamada ponta a ponta pelo `/docs`: criar cofre, gravar segredo, ler de volta. É aqui que aparecem divergências de AAD | *(idem — sentados juntos)* |
| **4 — Prova e documentação** | Os cinco testes, capturas e `resultados.md` | README consolidado e `requirements.txt` |
| **5 — Entrega** *(juntos)* | Conferência do `git status` e push final | *(idem — sentados juntos)* |

## 3.3 Envio ao GitHub (§14.3)

Repositório **público**, criado **sem adicionar arquivo inicial algum**. Depois, na pasta do projeto:

```bash
git init                      # inicia o controle de versão na pasta
git add .                     # marca os arquivos para envio
git status                    # CONFIRA: o .env não pode aparecer aqui
git commit -m "Cofre de senhas com AES-GCM"
git branch -M main            # nomeia o ramo principal
git remote add origin https://github.com/USUARIO/REPOSITORIO.git
git push -u origin main       # envia o código
```

> **O `git status` da terceira linha é uma conferência obrigatória.** Se o `.env` constar da lista,
> interromper a sequência, verificar o `.gitignore` e rodar `git rm --cached .env` antes de
> prosseguir. **Uma credencial enviada ao GitHub permanece no histórico mesmo após ser removida
> em um envio posterior.**

- [ ] Endereço do repositório enviado pelo canal indicado em aula, dentro do prazo

## 3.4 Estrutura obrigatória do repositório (§14.1)

```
cofre-aes/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── cripto.py
│   ├── banco.py
│   └── modelos.py
├── sql/
│   └── esquema.sql          script da Etapa 2
├── testes/
│   ├── resultados.md        os cinco testes e o que se observou
│   └── evidencias/          capturas de tela
├── .env.exemplo
├── .gitignore
├── requirements.txt
└── README.md
```

---
---

# PARTE 4 — Regras invioláveis

## 4.1 Requisitos obrigatórios (§13.1)

| Requisito | Dono |
|---|---|
| AES-256 em modo GCM para **todas** as senhas armazenadas | João |
| PBKDF2 com HMAC-SHA-256, **no mínimo 210 000 iterações**, sal de 16 bytes por cofre | João |
| Nonce de 12 bytes, sorteado aleatoriamente a cada cifragem, **inclusive nas atualizações** | João + Saddi |
| AAD contendo os identificadores do cofre e do segredo | João + Saddi |
| **Tratamento explícito do `ValueError`**, com resposta HTTP apropriada | Saddi |
| Separação das camadas nos quatro arquivos (§0.13) | os dois |
| `.gitignore` impedindo o envio do `.env` e do ambiente virtual | Saddi |

## 4.2 Vedado (§13.2)

- **Armazenar a senha-mestra ou a chave derivada**, em qualquer forma ou local — inclusive em
  memória entre requisições
- Utilizar os modos **ECB ou CBC** no lugar do GCM
- Usar valor **fixo** de nonce ou de sal
- **Implementar o AES manualmente** — usar a PyCryptodome
- **Registrar senhas, chaves ou senhas-mestras em logs ou em chamadas de impressão**
- **Enviar o arquivo `.env` ao repositório**

## 4.3 Condição eliminatória (§15)

> A presença do arquivo `.env`, de senhas em texto claro ou de chaves fixas no código versionado
> **zera o critério de repositório e documentação e reduz em dois pontos a nota final**,
> independentemente da qualidade do restante do trabalho.

Vale para os dois, independentemente de quem cometeu.

---
---

# PARTE 5 — Apêndices

## Apêndice A — Os cinco testes em detalhe (§12) · dono: João

Cada teste confirma experimentalmente uma propriedade discutida na fundamentação.
Evidências em `testes/evidencias/`, resultados escritos em `testes/resultados.md`.

### Teste 1 — Nonces distintos

**Procedimento:** cadastrar **duas vezes a mesma senha**, com títulos diferentes, no mesmo cofre.
Consultar a tabela `segredos` no Supabase.

**Esperado:** os campos `nonce` e `criptograma` são **diferentes** nos dois registros, ainda que a
senha protegida seja idêntica.

### Teste 2 — Senha-mestra incorreta

**Procedimento:** solicitar a leitura de um segredo informando uma senha-mestra errada.

**Esperado:** resposta **401**, **sem qualquer conteúdo do segredo** no corpo da resposta.

### Teste 3 — O que o invasor enxerga

**Procedimento:** no Supabase, executar consulta direta à tabela e registrar o resultado:

```sql
select titulo, usuario, nonce, criptograma, etiqueta
from public.segredos;
```

**Esperado:** **nenhuma senha legível** — apenas cadeias em Base64 sem significado aparente.

### Teste 4 — Registro adulterado

**Procedimento:** ainda no Supabase, alterar manualmente um caractere do campo `criptograma` e
tentar ler pela API **com a senha-mestra correta**:

```sql
update public.segredos
set criptograma = 'X' || substring(criptograma from 2)
where id = 'coloque-aqui-o-id-do-segredo';
```

**Esperado:** resposta **500** indicando registro adulterado, e **nenhum texto claro devolvido**.
O `ValueError` levantado pela biblioteca deve estar **tratado**, e não exibido como falha não prevista.

### Teste 5 — Troca de criptogramas entre registros

**Procedimento:** copiar os campos `nonce`, `criptograma` e `etiqueta` de um segredo para **outro
segredo do mesmo cofre**, e tentar ler o segredo de destino.

**Esperado:** a leitura é **recusada**. O AAD amarra o criptograma ao identificador do registro de
origem, e a etiqueta não confere no registro de destino. Este teste demonstra o efeito prático dos
dados associados.

## Apêndice B — Erros comuns e como resolver (Apêndice B do enunciado)

| Sintoma | Causa provável e solução |
|---|---|
| `ModuleNotFoundError: No module named 'Crypto'` | O ambiente virtual não está ativo, ou a instalação foi feita fora dele. Ative e reinstale. O pacote **instala como `pycryptodome` e importa como `Crypto`** |
| `ValueError: MAC check failed` | Chave, nonce ou AAD diferentes dos usados na cifragem. Verifique se o AAD é montado da mesma forma nos dois sentidos e se o nonce lido é o do próprio registro |
| `KeyError: 'SUPABASE_URL'` | O `.env` não foi encontrado. Confirme o nome exato, a localização na raiz e a chamada a `load_dotenv()` antes do uso das variáveis |
| `TypeError: Object of type bytes is not JSON serializable` | Tentativa de gravar bytes direto no banco. Converta com `para_b64` antes da gravação |
| `new row violates row-level security policy` | As políticas de §8.3 não foram criadas, ou foram aplicadas a **apenas uma** das tabelas. Execute o script novamente |
| Servidor não recarrega após alterações | O `--reload` foi omitido, ou o arquivo alterado está fora da pasta observada. `Ctrl+C` e reinicie |
| A rota devolve 422 sem explicação aparente | O corpo enviado não corresponde ao modelo Pydantic. A resposta do FastAPI indica o campo divergente — leia o detalhe do erro |

## Apêndice C — Glossário (Apêndice A do enunciado)

| Termo | Significado |
|---|---|
| **AAD** | Dados associados. Informação não cifrada que entra no cálculo da etiqueta, vinculando o criptograma a um contexto |
| **Base64** | Representação de dados binários em caracteres de texto, para transporte em JSON e em colunas de texto |
| **Cabeçalho HTTP** | Campo de metadados de uma requisição, separado do corpo e da URL |
| **Etiqueta** | Os 16 bytes que autenticam o criptograma no GCM. Também chamada de *tag* |
| **KDF** | Função de derivação de chave. Transforma uma senha em uma chave de tamanho e qualidade adequados |
| **Nonce** | Valor usado uma única vez com uma dada chave. No GCM, 12 bytes aleatórios por cifragem |
| **Sal** | Bytes aleatórios não secretos que individualizam a derivação de chave de cada cofre |
| **Verificador** | Criptograma de uma frase fixa, usado para conferir a senha-mestra sem armazená-la |

## Apêndice D — Referências (§16)

- DWORKIN, M. *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC.* NIST Special Publication 800-38D. Gaithersburg: NIST, 2007.
- TURAN, M. S.; BARKER, E.; BURR, W.; CHEN, L. *Recommendation for Password-Based Key Derivation: Part 1 — Storage Applications.* NIST Special Publication 800-132. Gaithersburg: NIST, 2010.
- OPEN WORLDWIDE APPLICATION SECURITY PROJECT. *Password Storage Cheat Sheet.* OWASP Cheat Sheet Series, 2024.
- FERGUSON, N.; SCHNEIER, B.; KOHNO, T. *Cryptography Engineering: Design Principles and Practical Applications.* Indianapolis: Wiley, 2010.
- PYCRYPTODOME. Documentação oficial — `pycryptodome.readthedocs.io`
- FASTAPI. Documentação oficial — `fastapi.tiangolo.com`

## Apêndice E — Mapa de arquivos

Se um arquivo não está nesta lista, ele ainda não tem dono — combinem antes de criar.

| Arquivo | Dono | O que é |
|---|---|---|
| `app/__init__.py` | João | Arquivo vazio, marca o pacote |
| `app/cripto.py` | João | PBKDF2, AES-GCM e o verificador |
| `testes/resultados.md` | João | Os cinco testes e o que se observou |
| `testes/evidencias/` | João | Capturas de tela |
| `app/banco.py` | Saddi | Acesso ao Supabase |
| `app/modelos.py` | Saddi | Modelos Pydantic |
| `app/main.py` | Saddi | Rotas, códigos de resposta e orquestração |
| `sql/esquema.sql` | Saddi | Tabelas, índice e políticas |
| `README.md` | Saddi | Consolidado, com trechos do João |
| `.gitignore` | Saddi | Criado na Fase 0, antes do primeiro commit |
| `.env` | Saddi | **Local, nunca versionado** |
| `.env.exemplo` | Saddi | Valores fictícios, versionado |
| `requirements.txt` | Saddi | Gerado no fim, com as versões reais |
