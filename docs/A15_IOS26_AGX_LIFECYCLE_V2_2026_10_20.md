# A15 / iOS 26 AGX lifecycle V2

Date: 2026-10-20  
Branche: `codex/a15-ios26-private-research`  
Cible: `iPhone14,2`, A15, iOS 26.0.1, build `23A355`

## Périmètre

Cette révision poursuit l'observabilité du cycle de vie AGX existant. Elle ne
cherche pas à faire progresser la chaîne de privilèges. Aucun paquet MDSID non
vide, appel MMIO, écriture physique ou protégée, opération SPTM/PAPT, root
replacement, bootstrap ou installation de Sileo n'est ajouté.

La durée d'observation après l'appel borné reste limitée à 250 ms. La V2 ne
relance pas selector 25 et ne transforme pas l'enregistrement vide accepté en
preuve d'exécution d'un enregistrement non vide.

## 1. Défauts identifiés

### Confiance et diagnostic

- Les événements précédents ne distinguaient pas systématiquement l'opération,
  son code de retour, sa durée et l'état des ressources au moment du retour.
- Un identifiant de session et une horloge monotone manquaient pour corréler
  des événements issus de plusieurs lancements.
- `ready=1` pouvait être lu comme un état durable alors qu'il ne prouve ni la
  persistance du contexte firmware ni une assertion d'alimentation confirmée.
- Les états « assertion demandée », « assertion confirmée » et « contexte
  firmware maintenu » n'étaient pas explicitement représentés comme non testés.

### Nettoyage

- Le cleanup partagé était déjà centralisé et idempotent, mais son état final
  effaçait `pageLocked`, `connectionOpen` ou `serviceHeld` même lorsque
  `munlock`, `IOServiceClose` ou `IOObjectRelease` échouait.
- Les sorties partielles devaient continuer les étapes indépendantes tout en
  gardant visible la ressource dont la libération n'était pas confirmée.
- Les appels AGX importants n'avaient pas tous une mesure monotone bornée et un
  motif de fermeture exploitable dans le journal JSONL.

## 2. Correctifs apportés

### État structuré

`TitanAGXLifecycle` distingue maintenant :

- service détenu et connexion ouverte ;
- client créé ;
- buffer et ressources initialisés ;
- file créée et file disponible ;
- notification créée et liée ;
- page verrouillée et cleanup terminé ;
- identifiants de buffer, file et notification ;
- assertion d'alimentation et contexte firmware sous forme tri-état
  `YES` / `NO` / `NOT_TESTED`.

Chaque événement JSONL conserve le schéma existant et ajoute `session_id`,
`timestamp_monotonic_ns`, `operation`, `return_code`, `duration_ns`,
`resource_state` et `close_reason`. Les appels bornés selector 6, 12, 14, 24
et 25, ainsi que `IOServiceOpen`, `munlock`, `IOServiceClose` et
`IOObjectRelease`, utilisent le checkpoint opérationnel.

### Nettoyage fiable

- `munlock` ne fait disparaître `pageLocked` que si son retour est nul.
- `IOServiceClose` ne fait disparaître `connectionOpen` et `clientCreated` que
  si le retour Mach est `KERN_SUCCESS`.
- `IOObjectRelease` ne fait disparaître `serviceHeld` qu'après un retour nul.
- Les handles locaux sont neutralisés après tentative afin d'empêcher une
  double libération sur un chemin de sortie ultérieur.
- Le helper continue les étapes indépendantes après une erreur partielle,
  marque le résultat global en échec, et refuse silencieusement un second
  cleanup tout en journalisant `duplicate cleanup suppressed`.

### Analyse de cycle de vie

Les transitions sont journalisées explicitement pour la création du client,
des ressources, de la file, de la notification, de la liaison de notification
et du verrouillage de page. Les trois états de puissance/contexte restent
`NOT_TESTED`; aucune assertion de puissance n'est demandée et aucun maintien
du contexte firmware n'est prétendu.

## 3. Tests hors ligne

Le test `tools/a15_ios26/test_agx_lifecycle_v2.py` vérifie :

- la présence du contrat d'événements structurés ;
- les états `NOT_TESTED` et l'absence d'une promotion artificielle de `ready` ;
- l'unicité de l'appel selector 25 et son étiquette `empty-record` ;
- la centralisation du cleanup ;
- un modèle de nettoyage normal, d'échecs partiels et d'appel dupliqué.

Ces tests sont des `STATIC PASS` et des tests de modèle Python. Ils ne valident
pas le comportement du kernel, du firmware ou du téléphone.

Les contrôles globaux à exécuter pour cette révision sont :

```text
py -m unittest discover -s tools/a15_ios26 -p "test_*.py"
py tools/a15_ios26/check_research_integration.py
py -m compileall -q tools/a15_ios26
git diff --check
```

La compilation Objective-C/Xcode et l'exécution sur appareil restent
`NOT_TESTED` dans l'environnement Windows de développement. Aucun IPA V2 n'est
promu par ce changement et aucune nouvelle sonde n'est lancée sur l'iPhone.

## 4. Hypothèses encore ouvertes

- Le contrat exact et les effets du chemin MDSID non vide restent non vérifiés.
- Le callback effectif, les effets backend et le moment complet de libération
  des objets enfants AGX ne sont pas observés indépendamment.
- La présence de `queue+0x428`, l'état `ready` et l'incrément de l'index de
  commande décrivent l'acceptation de l'enregistrement vide, pas la survie du
  contexte firmware.
- Les assertions de puissance et la récupération après transition n'ont pas
  été exécutées.
- Le modèle Python ne peut pas reproduire une erreur Objective-C, Mach ou
  firmware réelle.

## 5. Observations nécessaires sur appareil

Une future observation autorisée devrait seulement vérifier la cohérence des
champs JSONL déjà présents : identifiant de session, durée monotone inférieure
à la fenêtre de 250 ms, codes de retour, états avant/après cleanup et motif de
fermeture. Elle devrait rester sur le parcours déjà borné et vide, sans retry,
sans paquet non vide et sans opération privilégiée.

## 6. Limites de validation

État de cette livraison :

- `STATIC PASS`: source, contrat de journalisation, bornes et tests Python ;
- `NOT_TESTED`: compilation Objective-C/Xcode et exécution sur l'iPhone ;
- `BLOCKED`: toute progression vers MDSID non vide, écriture privilégiée,
  SPTM/PAPT, bootstrap ou Sileo.

La V2 améliore donc la capacité à expliquer un futur résultat, mais ne constitue
ni un jailbreak fonctionnel ni une preuve d'accès rootless/root.
