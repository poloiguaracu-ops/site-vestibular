# Banco de dados do Vestibular UniFil 2027

Esta pasta contém a primeira etapa do banco de dados do sistema.

## O que será armazenado

- Dados cadastrais dos candidatos;
- inscrições e protocolos únicos;
- até três opções de curso por inscrição;
- situação e histórico de pagamentos;
- local, sala e horário de prova;
- situação do resultado;
- usuários administrativos, sessões e histórico de alterações.

## Criar o banco no Cloudflare D1

No terminal, dentro da pasta do projeto:

```bash
npx wrangler login
npx wrangler d1 create unifil-vestibular-2027
```

O Cloudflare exibirá um identificador chamado `database_id`. Guarde esse identificador: ele será usado na configuração do Worker.

Depois de criar o banco, aplique a estrutura:

```bash
npx wrangler d1 execute unifil-vestibular-2027 --remote --file=database/schema.sql
```

Para conferir as tabelas:

```bash
npx wrangler d1 execute unifil-vestibular-2027 --remote --command="SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
```

## Importante antes de abrir inscrições reais

O formulário atual ainda é demonstrativo. Não solicite nem envie dados reais até concluirmos a API, autenticação, painel administrativo, aviso de privacidade, controles de acesso e testes. Senhas serão armazenadas somente como hash; sessões e dados pessoais não devem ficar em arquivos públicos ou no navegador.
