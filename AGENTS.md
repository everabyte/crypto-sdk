# crypto-sdk — Guide pour agents IA

SDK de chiffrement côté client Everabyte (`evb-e2ee-v1`) : noyau Rust
(`core/`), binding WASM/TypeScript (`bindings/wasm`), binding Dart FFI
(`bindings/dart`). Le protocole est spécifié dans [`PROTOCOL.md`](PROTOCOL.md) ;
l'utilisation est documentée dans [`README.md`](README.md) et sur
https://docs.everabyte.com (section Zero-Knowledge SDK).

**Règle du dépôt racine Everabyte** : toute règle transversale appartient à
l'`AGENTS.md` du service concerné — ce fichier est autonome et suffit.

## 1. RÈGLE DE VERSIONING OBLIGATOIRE (tout agent IA)

**Toute modification fonctionnelle du code (noyau, bindings, format wire,
générateur de vecteurs) DOIT incrémenter la version** conformément à la
politique ci-dessous. Ne PAS incrémenter pour : lecture/analyse de code,
commentaires, formatage, doc sans impact produit (`README`/`PROTOCOL`
informatifs sans changement de contrat).

### 1.1 Format et plafonds

- Format : `MAJOR.MINOR.BUILD` — fichier **`VERSION`** à la racine =
  **source de vérité unique**.
- **Départ à 0** pour chaque segment à la création d'une ligne de version ;
  incrémentation de +1 à chaque pas.
- **Plafond strict = 100 par segment** :
  - `BUILD` : `x.y.100` est le dernier de la ligne — jamais `x.y.101`.
    Au dépassement → `MINOR` +1 et `BUILD` = 0 (`0.1.100` → `0.2.0`).
  - `MINOR` : même plafond — jamais `x.101.z`. Au dépassement → `MAJOR` +1
    et `MINOR` = `BUILD` = 0 (`0.100.100` → `1.0.0`).
- **Jamais de report** : une montée de segment repart à 0 — l'ancien
  compteur n'est jamais transporté (`0.1.100` → `0.2.0`, pas `0.2.100`).
- Une version déjà tagguée/publiée n'est **jamais** réécrite ni réutilisée.

### 1.2 Quel incrément pour quel changement

| Changement | Incrément |
|---|---|
| Build/publi interne (fix, doc de contrat, vec/metadata, refacto sans changement d'API ni de wire format) | `BUILD` +1 |
| Nouvelle fonction/paramètre optionnel, nouveau scheme id **lisible** ajouté, nouvelle entrée de grille de vecteurs | `MINOR` +1, `BUILD` = 0 |
| Changement du format wire (`v` bumpé, nouveau magic, sémantique AAD/nonce modifiée) ou breaking API (signature supprimée/retirée) | `MAJOR` +1, `MINOR` = `BUILD` = 0 |

Rappel protocole : tout changement de wire format est **toujours** un nouveau
scheme id ou un bump du champ `v` avec dispatch lisible — jamais une
réinterprétation silencieuse des octets existants (voir `PROTOCOL.md` §10).

### 1.3 Procédure d'incrément (dans l'ordre)

1. Mettre à jour **`VERSION`** (source de vérité).
2. Propager la même valeur dans **tous les miroirs** :
   `core/Cargo.toml`, `bindings/wasm/Cargo.toml`,
   `bindings/wasm/pkg/package.json`, `bindings/wasm/pkg-node/package.json`,
   `bindings/dart/pubspec.yaml`, `bindings/dart/rust/Cargo.toml`
   (+ le champ `version` rapporté par les bindings si présent).
3. Si `core/` a changé : régénérer les WASM prébuilds
   (`wasm-pack build bindings/wasm --target web --out-dir pkg` et
   `--target nodejs --out-dir pkg-node`) et les committer.
4. **Gates obligatoires avant commit** :
   `cargo test -p evb-e2ee-core` (23 + 9 incluant les vecteurs figés),
   `dart test` dans `bindings/dart` (10), suite de vecteurs figés de chaque
   client consommateur si la grille a été resynchronisée.
5. Commit : `chore(release): bump version to X.Y.Z` (+ éventuel `feat`/`fix`
   séparé pour le changement lui-même).
6. **Tag git `vX.Y.Z`** = point de release ; un tag n'est créé qu'après les
   gates verts et n'est jamais déplacé.

### 1.4 Interdictions

- Jamais d'édition d'un miroir sans `VERSION` (désalignement = bug).
- Jamais `x.y.101`+ ni `x.101.z`+ (plafond 100 absolu par segment).
- Jamais de commit d'artefacts de build (`target/`, `.dart_tool/` — cf.
  `.gitignore`) ni de fichier sensible (`*.key`, `*.pem`, `.env*` — cf.
  `.gitignore`).
- Jamais de publication (tag, Release, crates.io/npm/pub.dev) sans les
  gates de 1.3 verts.
