# API do Vestibular — Cloudflare Worker

## Rotas preparadas
- GET /api/health — verifica API e D1.
- POST /api/register — cria candidato, inscrição, protocolo e opções de curso.
- POST /api/login — autentica candidato por CPF e senha.
- GET /api/me — consulta somente a inscrição da sessão autenticada.
- POST /api/logout — encerra a sessão.

## Publicação pendente
1. Criar o banco D1 unifil-vestibular-2027 no Cloudflare.
2. Substituir o database_id em wrangler.toml pelo ID real.
3. Executar o schema: npx wrangler d1 execute unifil-vestibular-2027 --remote --file=../database/schema.sql
4. Na pasta worker, executar npm install -D wrangler, npx wrangler login e npx wrangler deploy.
5. Configurar uma rota /api/* no mesmo domínio do site e testar todos os endpoints com dados fictícios.

## Segurança e limites
- Senhas com PBKDF2-SHA-256 e salt individual.
- Sessões aleatórias armazenadas como hash em cookie HttpOnly/Secure/SameSite=Strict.
- CPF validado antes de gravar.
- Ainda não existe painel administrativo, recuperação de senha, integração de cobrança ou rate limiting.
- Validar cursos, locais e modalidades com a oferta oficial; revisar aviso de privacidade/LGPD, backups, monitoramento e segurança antes de inscrições reais.
- O formulário público continua em modo demonstrativo até a API estar publicada e testada.
