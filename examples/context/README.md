# Context directory

Drop anything that helps MASAgent test deeper here, then pass `--context ./context/`:

- `openapi.yaml` / `openapi.json` — REST API schema (endpoints, params, auth)
- `schema.graphql` — GraphQL schema for native GraphQL testing
- `architecture.md` — how the system is put together, trust boundaries
- `credentials.json` — **test** credentials for authenticated and multi-role
  testing (IDOR/BOLA needs at least two roles). Never real production secrets you
  are not authorized to use.
- `notes.md` — anything else: known endpoints, feature flags, rate-limit hints

More context means a more thorough test. Everything here stays local to the run;
MASAgent never sends it anywhere except, where relevant, to the model router you
configured (and never to an out-of-scope host).
