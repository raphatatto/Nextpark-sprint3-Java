# Nextpark

Nextpark é uma aplicação web construída com Spring Boot para administrar um pátio de motos. Ela oferece autenticação baseada em perfis, cadastro de clientes, gestão de vagas, controle das motos estacionadas e histórico das movimentações realizadas pelos gestores do pátio.

## Integrantes
Tiago Ribeiro Capela - RM 558021

Raphaela Oliveira Tatto - RM 554983

## Link do video
https://youtu.be/vhddup5DgIQ

## Funcionalidades

- **Autenticação via formulário e controle de acesso por perfil**: somente páginas públicas, como login e cadastro, são liberadas sem autenticação; rotas administrativas exigem o papel de gerente. 【F:src/main/java/br/com/fiap/nextpark/config/SecurityConfig.java†L13-L31】
- **Usuário padrão para acesso gerente**: ao iniciar a aplicação é criado (ou atualizado) automaticamente o usuário `gerente` com a senha configurada em `app.security.admin.password` (padrão `gerente123`). 【F:src/main/java/br/com/fiap/nextpark/config/AdminUserInitializer.java†L15-L74】
- **Cadastro de novos clientes** diretamente pela tela `/register`; o sistema salva o usuário com perfil `CLIENTE` e senha criptografada. 【F:src/main/java/br/com/fiap/nextpark/controller/RegisterController.java†L19-L30】
- **Gestão de vagas (GERENTE)**: criar, editar, listar e excluir vagas de estacionamento com controle de status. Clientes não têm acesso a essas telas. 【F:src/main/java/br/com/fiap/nextpark/controller/VagaController.java†L14-L49】【F:src/main/java/br/com/fiap/nextpark/service/VagaService.java†L25-L55】
- **Gestão de motos (CLIENTE e GERENTE)**: clientes registram suas motos, editam informações e acompanham o status; gerentes conseguem visualizar todas as motos, desalocar, alocar ou mover entre vagas livres. 【F:src/main/java/br/com/fiap/nextpark/controller/MotoController.java†L27-L88】【F:src/main/java/br/com/fiap/nextpark/service/MotoService.java†L35-L139】
- **Histórico de movimentações**: cada alocação, transferência ou exclusão gera registro consultável por moto. 【F:src/main/java/br/com/fiap/nextpark/controller/MotoController.java†L90-L94】【F:src/main/java/br/com/fiap/nextpark/service/MotoService.java†L141-L154】
- **Promoção de usuários a gerente**: administradores existentes podem promover outras contas para o papel `GERENTE`. 【F:src/main/java/br/com/fiap/nextpark/controller/UsuarioController.java†L8-L22】
- **Tratamento global de erros** com mensagens amigáveis para violações de regra de negócio, restrições de banco e acessos negados. 【F:src/main/java/br/com/fiap/nextpark/web/GlobalExceptionHandler.java†L12-L56】

## Arquitetura e stack

- **Linguagem**: Java 17.
- **Frameworks principais**: Spring Boot (Web, Data JPA, Security), Thymeleaf, Flyway e Lombok. 【F:pom.xml†L24-L79】
- **Banco de dados**: Azure SQL Database (SQL Server), com versionamento de esquema e dados usando Flyway. 【F:src/main/resources/db/migration/V1__baseline.sql†L1-L43】【F:src/main/resources/db/migration/V2__seed_usuarios.sql†L1-L2】【F:src/main/resources/db/migration/V3__seed_vagas.sql†L1-L3】
- **Front-end**: páginas Thymeleaf servidas pelo Spring MVC com assets estáticos em `/static`.

## Pré-requisitos

1. **Java 17** (JDK) instalado e configurado no `PATH`.
2. **Maven 3.9+** ou uso do wrapper (`mvnw`).
3. **Azure SQL Database** acessível (porta 1433 liberada). Configure a URL JDBC, usuário e senha via variáveis de ambiente `AZURE_SQL_URL`, `AZURE_SQL_USER` e `AZURE_SQL_PASSWORD`. 【F:src/main/resources/application.properties†L1-L21】
4. Usuário com privilégios suficientes para executar as migrações Flyway no schema configurado (`AZURE_SQL_SCHEMA`, padrão `dbo`). 【F:src/main/resources/application.properties†L9-L17】

## Configuração do banco e dados iniciais

1. Defina as variáveis de ambiente com as credenciais do Azure SQL antes de iniciar a aplicação ou executar o Flyway.
2. Atualize o seed do gerente em `V2__seed_usuarios.sql` com um hash BCrypt real antes de executar as migrações. Você pode gerar um hash executando `new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder().encode("suaSenha")` em um REPL Spring ou pequena classe utilitária. 【F:src/main/resources/db/migration/V2__seed_usuarios.sql†L1-L2】
3. Execute as migrações:
   ```bash
   ./mvnw flyway:migrate
   ```
   Isso criará as tabelas, usuário gerente inicial e vagas de exemplo descritos nos scripts `V1__baseline.sql` e `V3__seed_vagas.sql`. 【F:src/main/resources/db/migration/V1__baseline.sql†L1-L43】【F:src/main/resources/db/migration/V3__seed_vagas.sql†L1-L3】

## Executando a aplicação

1. Compile o projeto (opcional, mas recomendado na primeira execução):
   ```bash
   ./mvnw clean package
   ```
2. Inicie o servidor Spring Boot:
   ```bash
   ./mvnw spring-boot:run
   ```
3. A aplicação será iniciada em `http://localhost:8080/` por padrão.

### Variáveis de ambiente locais

Exemplo de configuração em sistemas Unix-like:

```bash
export AZURE_SQL_URL="jdbc:sqlserver://<servidor>.database.windows.net:1433;database=<nome>;encrypt=true;trustServerCertificate=false;loginTimeout=30"
export AZURE_SQL_USER="<usuario>"
export AZURE_SQL_PASSWORD="<senha>"
export AZURE_SQL_SCHEMA="dbo" # opcional; use se estiver trabalhando com outro schema
```

No Windows (PowerShell):

```powershell
$Env:AZURE_SQL_URL = "jdbc:sqlserver://<servidor>.database.windows.net:1433;database=<nome>;encrypt=true;trustServerCertificate=false;loginTimeout=30"
$Env:AZURE_SQL_USER = "<usuario>"
$Env:AZURE_SQL_PASSWORD = "<senha>"
$Env:AZURE_SQL_SCHEMA = "dbo" # opcional
```

### Configurando no Azure App Service

1. Acesse o portal do Azure e abra o App Service da aplicação.
2. Em **Configurações** > **Variáveis de Aplicativo**, adicione as chaves `AZURE_SQL_URL`, `AZURE_SQL_USER`, `AZURE_SQL_PASSWORD` e, se necessário, `AZURE_SQL_SCHEMA`.
3. O valor de `AZURE_SQL_URL` deve seguir o formato `jdbc:sqlserver://<servidor>.database.windows.net:1433;database=<nome>;encrypt=true;trustServerCertificate=false;loginTimeout=30`.
4. Salve as alterações e reinicie o App Service para aplicar as novas configurações.

## Fluxo de acesso e credenciais

- **Login**: acesse `http://localhost:8080/login`. O usuário gerente criado via Flyway (por exemplo, `gerente` + senha usada no hash BCrypt) já possui permissão para gerenciar vagas e motos.
- **Cadastro de clientes**: novos usuários podem se registrar em `http://localhost:8080/register`. Eles recebem automaticamente o perfil `CLIENTE` e podem cadastrar suas próprias motos. 【F:src/main/java/br/com/fiap/nextpark/controller/RegisterController.java†L19-L30】
- **Promoção a gerente**: após logado como gerente, acesse a ação de promoção (`POST /usuario/{id}/promover`) para elevar um cliente a gerente. 【F:src/main/java/br/com/fiap/nextpark/controller/UsuarioController.java†L16-L22】

## Rotinas de operação

- **Gerenciar vagas**: disponível apenas para gerentes em `/vaga`. Permite criar, editar e remover vagas mantendo os vínculos com motos. 【F:src/main/java/br/com/fiap/nextpark/controller/VagaController.java†L21-L49】【F:src/main/java/br/com/fiap/nextpark/service/VagaService.java†L25-L55】
- **Gerenciar motos**: clientes veem apenas suas motos; gerentes visualizam todas, pesquisam por placa/modelo (`?q=`) e podem alocar/desalocar vagas livres. 【F:src/main/java/br/com/fiap/nextpark/controller/MotoController.java†L27-L88】
- **Consultar histórico**: link "Histórico" na listagem de motos mostra as movimentações em ordem decrescente de data. 【F:src/main/java/br/com/fiap/nextpark/controller/MotoController.java†L90-L94】【F:src/main/java/br/com/fiap/nextpark/service/MotoService.java†L141-L154】
- **Mensagens de erro**: regras violadas (por exemplo, placa duplicada ou código de vaga repetido) exibem mensagens amigáveis via tratamento global. 【F:src/main/java/br/com/fiap/nextpark/web/GlobalExceptionHandler.java†L20-L56】

## Testes automatizados

Execute todos os testes unitários e de integração com Maven:
```bash
./mvnw test
```

## Estrutura do projeto

```
├── src/main/java
│   ├── br/com/fiap/nextpark/config        # Configurações de segurança e recursos estáticos
│   ├── br/com/fiap/nextpark/controller    # Controladores MVC (auth, motos, vagas, usuários)
│   ├── br/com/fiap/nextpark/model         # Entidades e enums do domínio
│   ├── br/com/fiap/nextpark/repository    # Repositórios Spring Data
│   ├── br/com/fiap/nextpark/security      # Usuários, roles e UserDetailsService
│   └── br/com/fiap/nextpark/service       # Regras de negócio e integrações com repositórios
├── src/main/resources
│   ├── db/migration                       # Scripts Flyway (schema + seeds)
│   ├── templates                          # Páginas Thymeleaf
│   └── static                             # CSS/JS
└── pom.xml                                # Dependências e plugins Maven
```


