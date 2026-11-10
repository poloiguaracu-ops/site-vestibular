# Banco de dados — Vestibular UniFil 2027

A configuração ativa do sistema está na raiz do repositório, em `wrangler.jsonc`, e a estrutura oficial do D1 está em `migrations/0001_initial_schema.sql`.

## Banco configurado

- Nome: `unifil-vestibular-2027`
- Binding usado pelo Worker: `DB`
- Migrações: pasta `migrations/`

## Aplicar as migrações

Na pasta raiz do projeto, use:

```bash
npx wrangler d1 migrations apply unifil-vestibular-2027 --remote
```

Para conferir as tabelas:

```bash
npx wrangler d1 execute unifil-vestibular-2027 --remote --command="SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
```

## Importante

Não use uma estrutura SQL antiga ou alternativa. O arquivo `database/schema.sql` é mantido igual à migração oficial para evitar divergências.

O Worker ativo é `src/index.js`. Ele exige os Secrets `CPF_HASH_KEY` e `DATA_ENCRYPTION_KEY`; esses valores devem ser cadastrados em **Settings → Variables & Secrets → Production** no Worker `site-vestibular`. Não os coloque no GitHub, no `wrangler.jsonc` ou nas variáveis exclusivas de Build.

Não envie dados reais de candidatos até que o endpoint de saúde confirme as duas chaves e os testes de inscrição e proteção de dados sejam concluídos.
