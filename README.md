# ms-fastapi-template

<!-- REPO-METADATA:START -->
<div align="center">

[![Repo Size](https://img.shields.io/github/repo-size/Ouros-App/ms-fastapi-template?style=flat-square&label=REPO%20SIZE)](https://github.com/Ouros-App/ms-fastapi-template)
[![Languages](https://img.shields.io/github/languages/count/Ouros-App/ms-fastapi-template?style=flat-square&label=LANGUAGES)](https://github.com/Ouros-App/ms-fastapi-template/languages)
[![Forks](https://img.shields.io/github/forks/Ouros-App/ms-fastapi-template?style=flat-square&label=FORKS)](https://github.com/Ouros-App/ms-fastapi-template/network/members)
[![Issues](https://img.shields.io/github/issues/Ouros-App/ms-fastapi-template?style=flat-square&label=ISSUES)](https://github.com/Ouros-App/ms-fastapi-template/issues)
[![Pull Requests](https://img.shields.io/github/issues-pr/Ouros-App/ms-fastapi-template?style=flat-square&label=PULL%20REQUESTS)](https://github.com/Ouros-App/ms-fastapi-template/pulls)

</div>
<!-- REPO-METADATA:END -->

Template mínimo para iniciar um microsserviço com FastAPI.

## Status e escopo

A implementação atual expõe apenas uma API básica com dois endpoints:

- `GET /`: retorna `{"message": "FastAPI microservice is running"}`.
- `GET /health`: retorna `{"status": "ok"}`.

O projeto já contém a separação inicial entre API, configuração, schemas, serviços, repositórios e modelos. As pastas `models`, `repositories` e `services` ainda não possuem implementação além de seus arquivos de pacote.

## Recursos e componentes

- FastAPI com metadados definidos em `app/core/config.py`.
- Schemas Pydantic em `app/schemas/common.py`.
- Rotas registradas por `app/main.py`.
- `Dockerfile` para execução com Uvicorn.
- `run.sh` para criar, recriar, remover e listar containers Docker.
- `run_compose.sh` para gerar arquivos Compose temporários e executar instâncias numeradas.

## Pré-requisitos

- Python e `pip`.
- Docker para os fluxos baseados em container.
- Bash para executar `run.sh` e `run_compose.sh`.

As dependências Python estão fixadas em:

- `fastapi==0.115.6`
- `uvicorn[standard]==0.34.0`

## Configuração

O arquivo `.env.example` contém:

```dotenv
APP_PORT=8000
APP_NAME=fastapi_microservice
```

Copie-o para `.env` quando usar os scripts ou o `Dockerfile`:

```bash
cp .env.example .env
```

`APP_PORT` e `APP_NAME` são usados pelos scripts e pelo container. Os metadados da aplicação definidos em `Settings` ainda são constantes no código.

## Instalação e execução local

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

A aplicação fica disponível em `http://localhost:8000`. A documentação interativa do FastAPI fica em `/docs` e o schema OpenAPI em `/openapi.json`.

## Execução com Docker

`run.sh` exige um `.env` com `APP_NAME` e oferece os modos abaixo:

```bash
./run.sh
./run.sh --reboot NUMERO
./run.sh --remove NUMERO
./run.sh --list
```

`run_compose.sh` também exige `.env` com `APP_NAME`, detecta `docker compose` ou `docker-compose`, gera o Compose da instância e aceita:

```bash
./run_compose.sh
./run_compose.sh --rebuild
./run_compose.sh --rebuild NUMERO
./run_compose.sh --reboot NUMERO
./run_compose.sh --bind NUMERO
./run_compose.sh --help
```

Não há um `docker-compose.yml` estático neste repositório. O script `run_compose.sh` gera um arquivo temporário para cada instância.

## Testes e qualidade

O diretório `tests/` contém apenas `__init__.py`; não há casos de teste automatizados implementados no estado atual.

## Estrutura do projeto

```text
.
├── app/
│   ├── api/routes.py
│   ├── core/config.py
│   ├── models/
│   ├── repositories/
│   ├── schemas/common.py
│   ├── services/
│   └── main.py
├── tests/
├── .env.example
├── Dockerfile
├── requirements.txt
├── run.sh
└── run_compose.sh
```

## Limitações conhecidas

O `Dockerfile` atualmente copia um arquivo `.env` e valida arquivos em `app/templates/workflows/`, mas esses caminhos não aparecem na árvore atual do repositório. Portanto, o build Docker não é considerado um fluxo pronto sem ajustar essa divergência.

## Contribuição

Faça alterações em uma branch própria e use os templates de pull request disponíveis em `.github/PULL_REQUEST_TEMPLATE`.

## Licença

Este projeto está sob a licença MIT. Consulte o arquivo [LICENSE](LICENSE).


## Principais contribuidores

<!-- CONTRIBUTORS:START -->
- [@Nicolas25vlad](https://github.com/Nicolas25vlad) — 14 contribuições
- [@Andre-Roger](https://github.com/Andre-Roger) — 1 contribuições
- [@juwata](https://github.com/juwata) — 1 contribuições
<!-- CONTRIBUTORS:END -->

> Atualizado automaticamente semanalmente pelo workflow de metadados do README.
