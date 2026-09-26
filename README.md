# Projeto Cofre AES

## GRUPO DO TRABALHO:

João Marcelo Angeli

Vitor Saddi Ribeiro

## 🔐 Sobre o Projeto

O **Projeto Cofre AES** é um sistema projetado para o armazenamento seguro de informações sensíveis, utilizando o padrão de criptografia AES (Advanced Encryption Standard). A aplicação é desenvolvida em Python e conta com uma arquitetura modular que separa as regras de negócio, a lógica de criptografia e a persistência em banco de dados.

## 📂 Estrutura do Repositório

O projeto está organizado da seguinte forma:

* **`app/`**: Diretório principal da aplicação.

  * `main.py`: Ponto de entrada e orquestração do sistema.

  * `cripto.py`: Módulo responsável pelas rotinas de criptografia e descriptografia AES.

  * `banco.py`: Módulo de conexão e operações com o banco de dados.

  * `modelos.py`: Estruturas de dados e modelagem da aplicação.

  * `__init__.py`: Arquivo de inicialização do pacote.

* **`SQL/`**: Contém os scripts de banco de dados.

  * `esquema.sql`: Script de criação das tabelas e esquemas necessários para rodar o cofre.

* **`testes/`**: Diretório dedicado à garantia de qualidade e validação.

  * `resultados.md`: Relatório com as conclusões e resultados dos testes executados.

  * `evidencias/`: Pasta contendo os arquivos de log e texto (`teste_0.txt` a `teste_5.txt`) gerados durante as validações.

* **Documentação e Configuração**:

  * `.env.exemplo`: Modelo de variáveis de ambiente necessárias para a execução (chaves, credenciais).

  * `requirements.txt`: Lista de dependências e bibliotecas Python utilizadas no projeto.

  * `.gitignore`: Arquivo de exclusão do Git (ignora `__pycache__`, `.env`, ambientes virtuais, etc).

## 👥 Divisão de Tarefas

O desenvolvimento foi modularizado para otimizar o fluxo de trabalho. As frentes de trabalho foram divididas abrangendo:

1. **Modelagem de Banco de Dados**: Criação do `esquema.sql` e conexão no `banco.py`.

2. **Engenharia de Criptografia**: Implementação dos algoritmos no `cripto.py` garantindo o correto uso do AES.

3. **Integração e Lógica de Negócio**: Desenvolvimento do `main.py` e `modelos.py`.

4. **Garantia de Qualidade**: Criação de casos de testes e coleta de evidências.

## 📊 Resultados Obtidos

Os testes de validação do sistema foram registrados na pasta `testes/`. Conforme documentado e corroborado pelas evidências em texto (`teste_0.txt` a `teste_5.txt`), obtivemos os seguintes resultados:

* **Efetividade da Criptografia**: Os dados foram cifrados corretamente através do módulo `cripto.py`, impossibilitando a leitura em texto claro no banco de dados.

* **Integridade na Recuperação**: A descriptografia provou-se exata, recuperando a informação original sem perda ou corrupção de bytes durante o trânsito entre o banco e a aplicação.

* **Isolamento de Ambiente**: As variáveis sensíveis foram lidas adequadamente a partir do `.env` mapeado pelo arquivo de exemplo, não expondo chaves no código-fonte.

## 🚀 Como Executar o Projeto

1. **Clone o repositório e acesse a pasta do projeto.**

2. **Crie e ative um ambiente virtual (recomendado)**:

   ```
   python -m venv .venv
   source .venv/bin/activate  # Linux/Mac
   # ou .venv\Scripts\activate no Windows
   
   ```

3. **Instale as dependências**:

   ```
   pip install -r requirements.txt
   
   ```

4. **Configure o ambiente**:

   * Copie o arquivo `.env.exemplo` para um novo arquivo chamado `.env`.

   * Preencha as variáveis necessárias (como sua chave AES e credenciais de acesso ao banco).

5. **Prepare o Banco de Dados**:

   * Execute o script `SQL/esquema.sql` no seu gerenciador de banco de dados para instanciar as tabelas.

6. **Inicie a Aplicação**:

   ```
   python app/main.py
   
   ```
