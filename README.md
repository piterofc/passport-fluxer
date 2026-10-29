# passport-fluxer

Estratégia do [Passport](https://www.passportjs.org/) para **entrar com Fluxer** (OAuth2 *authorization code* + PKCE).
Construída em cima do [`passport-custom`](https://www.npmjs.com/package/passport-custom), seguindo a [documentação OAuth2 do Fluxer](https://docs.fluxer.app/http-api/oauth2/).

- Descobre a URL da API automaticamente via `/.well-known/fluxer` (funciona em instâncias self-hosted)
- `state` + PKCE (S256) ligados por padrão
- Perfil já mapeado (`id`, `username`, `displayName`, `email`, ...)
- Sem dependências além do `passport-custom` (usa o `fetch` nativo do Node 18+)
- Tipos TypeScript incluídos, funciona em CommonJS e ESM
- Helpers para `refreshToken()` e `revokeToken()`

## Instalação (direto do GitHub)

```bash
npm install github:piterofc/passport-fluxer passport
# ou fixando uma versão/tag:
npm install github:piterofc/passport-fluxer#v0.1.0 passport
```

Não há etapa de build: o código é JavaScript puro, então instalar pelo GitHub funciona sem `prepare`/`dist`.

Você também precisa de um middleware de sessão (ex.: `express-session`) para guardar o `state` e o verificador PKCE entre o redirect e o callback.

## Antes de usar

1. Crie uma aplicação no Fluxer (rotas de [Applications](https://docs.fluxer.app/http-api/applications/)) e anote o **client ID** e o **client secret**.
2. Registre o `callbackURL` como *redirect URI* da aplicação.

## Uso

```js
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const { Strategy: FluxerStrategy } = require('passport-fluxer');

passport.use(
  new FluxerStrategy(
    {
      clientID: process.env.FLUXER_CLIENT_ID,
      clientSecret: process.env.FLUXER_CLIENT_SECRET,
      callbackURL: 'https://meusite.com/auth/fluxer/callback',
      scope: ['identify', 'email'],
    },
    async (accessToken, refreshToken, profile, done) => {
      // Busque/crie o usuário no seu banco.
      // IDs do Fluxer são snowflakes: mantenha como string, nunca converta para Number.
      const user = await Users.findOrCreate({ fluxerId: profile.id, name: profile.displayName });
      done(null, user);
    },
  ),
);

const app = express();
app.use(session({ secret: '...', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

app.get('/auth/fluxer', passport.authenticate('fluxer'));
app.get('/auth/fluxer/callback', passport.authenticate('fluxer', { failureRedirect: '/login', successRedirect: '/' }));
```

ESM / TypeScript: `import { Strategy as FluxerStrategy } from 'passport-fluxer'`.
Um exemplo completo está em [`examples/express.js`](examples/express.js).

## Opções

| Opção | Padrão | Descrição |
|---|---|---|
| `clientID` | – | **Obrigatória.** ID da aplicação |
| `clientSecret` | – | **Obrigatória.** |
| `callbackURL` | – | **Obrigatória.** URL absoluta registrada na aplicação |
| `scope` | `['identify']` | String ou array. Escopos: `identify`, `email` (exige `identify`), `guilds`, `connections`, `bot` |
| `instanceURL` | `https://api.fluxer.app` | Origem da instância, usada na descoberta `/.well-known/fluxer`. Troque para usar uma instância self-hosted |
| `apiURL` | – | Pula a descoberta e usa esta base (a parte antes de `/v1`) |
| `name` | `'fluxer'` | Nome da estratégia no `passport.authenticate()` (útil para várias instâncias) |
| `state` | `true` | Envia e valida `state` (exige sessão) |
| `pkce` | `true` | Usa PKCE S256 (exige sessão) |
| `passReqToCallback` | `false` | Passa `req` como primeiro argumento do `verify` |
| `timeout` | `10000` | Timeout de cada requisição ao Fluxer, em ms |
| `fetch` | `globalThis.fetch` | Implementação de `fetch` customizada |
| `sessionKey` | `passport-fluxer:<name>` | Chave usada na sessão |

### Assinaturas do `verify`

```js
(accessToken, refreshToken, profile, done)                    // padrão
(accessToken, refreshToken, params, profile, done)            // com a resposta completa do token (scope, expires_in)
(req, accessToken, refreshToken, profile, done)               // passReqToCallback: true
(req, accessToken, refreshToken, params, profile, done)       // passReqToCallback: true + params
```

A variante é escolhida pelo número de parâmetros da função (como no `passport-oauth2`). O `verify` também pode ser `async`.
Em TypeScript, as duas variantes com `params` precisam dos parâmetros anotados (`params: TokenResponse`, `profile: Profile`, `done: DoneCallback`); as outras são inferidas sozinhas.
Para recusar o login: `done(null, false, { message: '...' })`.

### Opções por requisição

```js
app.get('/auth/fluxer', passport.authenticate('fluxer', {
  scope: ['identify', 'guilds'],
  prompt: 'none', // ou 'consent'
  authorizationParams: { guild_id: '123', permissions: '8' }, // parâmetros extras (ex.: escopo bot)
}));
```

## O objeto `profile`

```js
{
  provider: 'fluxer',
  id: '111222333444555666',      // string (snowflake)
  username: 'ana',
  discriminator: '0000',
  displayName: 'Ana',            // global_name, ou username se não houver
  globalName: 'Ana',
  avatar: 'abc123',              // hash do avatar (não é uma URL)
  avatarColor: 5,
  flags: 0,
  bot: false,
  system: false,
  // somente com o escopo `email`:
  email: 'ana@example.com',
  emailVerified: true,
  emails: [{ value: 'ana@example.com', verified: true }],
  _raw: '...', _json: { /* resposta original do /v1/oauth2/userinfo */ },
}
```

## Tokens

O access token dura 7 dias e o refresh token 30 dias. **O refresh token é de uso único**: ao renovar, salve o novo imediatamente, senão o usuário precisa autorizar de novo.

```js
const strategy = new FluxerStrategy(/* ... */);
passport.use(strategy);

const tokens = await strategy.refreshToken(oldRefreshToken); // { access_token, refresh_token, expires_in, scope, ... }
await strategy.revokeToken(tokens.refresh_token, 'refresh_token');
```

## Erros

Falhas ao falar com o Fluxer viram `FluxerError`, com `status`, `code` (ex.: `invalid_grant`) e `data`.
Se o usuário clicar em "negar" na tela de consentimento, é uma falha de autenticação normal (`failureRedirect`); outros erros do callback (como `consent_required` com `prompt=none`) chegam como erro.

## Self-hosted

```js
new FluxerStrategy({ /* ... */, instanceURL: 'https://chat.meudominio.com' }, verify);
```

## Desenvolvimento

```bash
npm install
npm test
```

Os testes sobem um servidor Fluxer falso e rodam o fluxo completo (redirect, state, PKCE, troca de código, perfil) através de um app Express real.

## Licença

MIT
