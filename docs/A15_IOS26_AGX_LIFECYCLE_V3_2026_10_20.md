# A15 / iOS 26 AGX lifecycle V3

Date: 2026-10-20  
Branche: `codex/a15-ios26-private-research`  
Cible: `iPhone14,2`, A15, iOS 26.0.1, build `23A355`

## 1. Synthese technique

La V2 est conservee. La V3 ajoute une verification de compilation macOS
declenchee manuellement et un validateur hors ligne du journal JSONL AGX.
Le workflow construit uniquement la cible Xcode `Titan` et ne lance pas le
workflow de production, ne cree pas d'IPA et n'installe rien sur un appareil.

La V2 avait deja ajoute les champs `session_id`, `timestamp_monotonic_ns`,
`operation`, `return_code`, `duration_ns`, `resource_state` et `close_reason`.
La revue V3 confirme leur presence et ajoute un controle automatique de leur
coherence.

## 2. Verification du code V2

Le fichier `Application/Dopamine/Exploits/Titan/exploit/titan.m` a ete relu
pour les points suivants :

- `TitanAGXLifecycle` conserve les etats client, buffer, ressources, file,
  notification, page et cleanup ;
- les appels bornes utilisent `clock_gettime_nsec_np(CLOCK_MONOTONIC)` et
  `mach_error_string` ;
- les operations de fermeture portent un `close_reason` ;
- `ready=1` reste seulement une observation et ne promouvoit pas la persistance
  du contexte firmware ;
- `munlock`, `IOServiceClose` et `IOObjectRelease` ne font disparaitre un etat
  que lorsque l'operation correspondante reussit ;
- la fermeture reste centralisee et idempotente ;
- l'appel selector 25 reste unique et limite a l'enregistrement vide.

Une correction defensive a ete ajoutee : `mach_error_string` est maintenant
declare explicitement par `<mach/error.h>`, ce qui evite de dependre d'un
include transitif du SDK.

Aucun probleme de type Mach/IOKit supplementaire n'a ete identifie par
l'analyse statique locale. La compilation Objective-C reste a confirmer sur
macOS/Xcode.

## 3. Compilation macOS preparee

Workflow ajoute :

`.github/workflows/a15-ios26-compile-check.yml`

Declenchement : `workflow_dispatch` uniquement.

Commandes derivees des fichiers reels du depot :

```text
make -C BaseBin .build .include
make -C BaseBin ChOma
make -C BaseBin libjailbreak
xcodebuild -project Application/Dopamine.xcodeproj \
  -target Titan -configuration Debug -sdk iphoneos \
  -derivedDataPath "$RUNNER_TEMP/titan-derived-data" \
  CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO
```

Ces etapes sont necessaires car la cible `Titan` reference les headers
`BaseBin/.include`, `BaseBin/libjailbreak/libjailbreak.dylib` et
`BaseBin/.build/libchoma.dylib`. Le workflow utilise un checkout recursif des
submodules, installe seulement `ldid` et les headers `libarchive`, puis
archive les journaux. Il ne lance pas `Application/Makefile`, qui produirait
`Dopamine.ipa`.

Etat de validation au moment de cette revision :

- compilation locale Windows : `NOT_TESTED`, Xcode absent ;
- GitHub Actions compile-check : `NOT_RUN`, workflow cree mais non declenche ;
- `BUILD PASS` : non declare tant qu'un run macOS ne fournit pas un resultat
  `xcodebuild` effectif.

## 4. Verification des journaux AGX

`tools/a15_ios26/audit_agx_lifecycle_log.py` valide hors ligne :

- les champs obligatoires de chaque evenement ;
- un `session_id` non vide et unique pour le run selectionne ;
- l'ordre monotone de `timestamp_monotonic_ns` ;
- les durees et codes de retour des enregistrements d'operation ;
- la presence de `resource_state` sur les resultats d'operation ;
- un `close_reason` pour `munlock`, `IOServiceClose` et `IOObjectRelease`.

Le resultat est JSON ou compact, avec `PASS`/`FAIL`, le run selectionne, le
nombre d'evenements et les erreurs. L'outil ne lit que le fichier fourni et ne
contacte ni l'appareil ni IOKit.

## 5. Analyse du blocage Power Lifecycle

Le code et les journaux existants permettent de distinguer :

| Etat | Observation | Statut |
| --- | --- | --- |
| Client AGX ouvert | `IOServiceOpen` reussi et connexion conservee | `OBSERVED` |
| File disponible | objet de file et champs de file valides | `OBSERVED` |
| Assertion demandee | aucune assertion normale demandee par la sonde | `NOT_TESTED` |
| Assertion confirmee | aucun accuse de puissance observe | `NOT_TESTED` |
| Contexte firmware maintenu | aucun test explicite de retention/reprise | `NOT_TESTED` |
| `ready=1` | octet lu dans l'objet de file | `OBSERVATION_ONLY` |

Les informations manquantes sont un evenement de demande d'alimentation, un
retour de confirmation, puis une mesure de retention du contexte apres la
fenetre d'observation. `ready=1`, un index de commande ou l'acceptation d'un
enregistrement vide ne suffit pas a les remplacer.

## 6. Preparation d'une validation appareil controlee

Cette procedure est preparatoire et ne se declenche pas automatiquement.

### Preconditions

- appareil exactement `iPhone14,2`, iOS `26.0.1`, build `23A355` ;
- journal precedent exporte et identifiant de run note ;
- IPA produite par un commit identifie et verifiee separement ;
- aucune transition de puissance forcee et aucun retry automatique ;
- confirmation que le parcours lance est celui de l'enregistrement vide deja
  accepte.

### Evenements attendus

`probe.entry`, `titan.lifecycle.start`, ouverture du client, creation du
buffer, creation/liaison de notification, creation de file, observation
selector 25 vide, fenetre de stabilisation bornee, puis cleanup avec codes de
retour et etats finaux.

### Interruption et conservation

Interrompre sur build cible incorrect, schema d'evenement invalide, retour Mach
inattendu, timeout de 250 ms, ressource non stable, modification non prevue du
buffer/pool ou echec de cleanup. Conserver le JSONL original, le hash de l'IPA,
le commit, le run id et le rapport de l'auditeur.

### Criteres

- `PASS` diagnostic : contrat JSONL valide, etats cohérents, cleanup confirme ;
- `FAIL` diagnostic : erreur de contrat, ressource non restauree ou cleanup
  non confirme ;
- `NOT_TESTED` : toute affirmation de puissance, retention firmware, MDSID non
  vide, ecriture physique/protegee ou passage SPTM/PAPT.

## 7. Resultats des tests locaux

Les controles locaux de cette revision sont :

```text
py -m unittest discover -s tools/a15_ios26 -p "test_*.py"
py -m compileall -q tools/a15_ios26
py tools/a15_ios26/check_research_integration.py
git diff --check
```

Resultats locaux :

- suite complete : `315` tests, `OK` (`STATIC PASS`) ;
- `compileall` : `PASS` ;
- `check_research_integration.py` : `PASS` ;
- `git diff --check` : `PASS`.

Ces resultats restent des `STATIC PASS` : ils ne remplacent pas un run macOS
et ne valident pas le comportement du kernel, du firmware ou de l'iPhone.

## 8. Points non demontres et prochaine etape

Restent non demontres : la compilation effective sur macOS, la retention du
contexte firmware, les effets d'un MDSID non vide, le passage SPTM/PAPT et tout
acces privilegie. La prochaine etape recommandee est de declencher une seule
fois le workflow compile-check sur un commit identifie, d'inspecter son log
`xcodebuild`, puis de mettre a jour ce document avec le resultat exact. Aucun
workflow de production ni test appareil ne doit etre lance automatiquement.

Cette phase ne constitue pas une validation de jailbreak fonctionnel.
