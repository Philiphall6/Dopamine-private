# A15 / iOS 26 Titan -> PHYSICAL_WRITE transition V10

Cible: `iPhone14,2`, Apple A15, iOS 26.0.1, build `23A355`.

Branche analysee: `codex/a15-ios26-private-research`.

Commit de base: `62cc1be` (V9).

## Perimetre

Cette revision est une analyse statique et hors ligne. Elle ne lance pas
`buildPhysRWPrimitive`, ne soumet pas de paquet AGX, ne reactive pas le
selector 25, n'accede pas au MMIO/RTKit, n'effectue pas d'ecriture physique
ou protegee, ne modifie pas SPTM/PAPT et n'installe pas de bootstrap.

Le resultat distingue les fonctions presentes dans le source, les observations
bornees deja obtenues sur l'A15 et les postconditions qui restent non
demontrees. Une fonction ou un callback non nul n'est pas traite comme une
preuve de capacite runtime.

## Resultat executif

Le diagramme fourni est correct pour l'intention generale, mais il manque une
distinction essentielle entre deux chemins:

1. Le chemin normal de Dopamine doit d'abord terminer un PPL/SPTM bypass,
   puis construire `physrw` et seulement ensuite elever les privileges.
2. Le chemin A15ACTIVE actuel est un chemin de diagnostic qui retourne
   volontairement avant la publication de Titan et avant toute construction de
   `physrw`.

La chaine actuellement demontree est donc:

```text
ClearSword
  -> KRW borne
  -> titan_init / target gate
  -> contexte noyau et patchfinder
  -> identite AGX/G14P et objets GART/IOUAT en lecture
  -> buffer partage, mutation temporaire et restauration V7
  -> selector 6, selector 14, selector 24
  -> preflight zero confirme
  -> selector 25 NOT_TESTED par garde compile-time
  -> titan_run retourne -1
  -> pas de publication titan_physwritebuf
  -> pas de buildPhysRWPrimitive
```

Le chemin normal complet attendu par le source, mais non demontre sur cette
cible, est:

```text
ClearSword KRW
  -> titan_run non-A15ACTIVE
  -> queue/notifications et soumissions IOGPU
  -> lecture IORVBAR et contexte RTKit/GFX
  -> copie et patchfinding du firmware GFX
  -> resolution des adresses physiques GFX
  -> construction du contexte ROP et de la fenetre PTE
  -> declenchement GFX et observation de krw_info.pte
  -> titan_run == 0
  -> gPrimitives.physwritebuf = titan_physwritebuf
  -> buildPhysRWPrimitive()
  -> libjailbreak_physrw_pte_init(false, 0) sur A15
  -> physrw_pte_handoff()
  -> publication des callbacks physrw_pte
  -> cleanup, elevation et bootstrap
```

Les deux diagrammes ne doivent pas etre fusionnes en une preuve continue:
la seconde chaine contient plusieurs transitions privilegiees qui ne sont pas
atteintes par les observations A15 fournies.

## Chaine d'execution reelle

### 1. Selection et chemin normal Dopamine

`DOExploitManager` charge les metadonnees des frameworks, filtre les flavors
avec `DOExploit -isSupported`, puis selectionne un exploit kernel, PAC et PPL
(`Application/Dopamine/Jailbreak/DOExploitManager.m:117-146`).

`DOJailbreaker -doExploitation`
(`Application/Dopamine/Jailbreak/DOJailbreaker.m:602-656`):

1. exige les exploits requis;
2. charge et execute l'exploit kernel;
3. initialise la traduction noyau et les primitives IOSurface;
4. execute le PAC bypass eventuel;
5. execute le PPL/SPTM bypass selectionne;
6. continue vers `buildPhysRWPrimitive` dans `runWithError:`.

Le commentaire officiel presuppose alors que le PPL bypass a fourni une
ecriture physique sans restriction. Cette presomption est un contrat du
parcours officiel, pas une observation A15.

`runWithError:` appelle ensuite `buildPhysRWPrimitive` avant
`cleanUpExploits`, puis `elevatePrivileges`, `prepareBootstrap`, les
trust-caches et les etapes launchd (`DOJailbreaker.m:1117-1157`). Aucun de ces
stades n'est atteint par le chemin A15ACTIVE.

### 2. Initialisation et arret A15ACTIVE

`Titan/Titan.m:14-27` est le seul point de publication de Titan:

```c
if (titan_run() != 0) return -1;
gPrimitives.physwritebuf = titan_physwritebuf;
```

L'initialisation du contexte A15 est acceptee par le target gate dans
`titan.m:2595-2717`, mais iOS 26.0.1 sur `iPhone14,2` active explicitement
`ios26_a15_active_probe`.

Dans `titan_run()` (`titan.m:2990-3010`), ce mode appelle
`titan_probe_agx_map_metadata()` puis retourne `-1`. Le chemin qui suit vers
`titan_setup_command_buffers`, `titan_parse_RTKit_information` et le ROP n'est
donc pas execute. Le test conditionnel de resolution IORVBAR immediatement
apres ce retour est inatteignable dans ce mode; cela explique une partie de la
difference entre les logs de diagnostic et le chemin normal, sans justifier de
modifier le garde-fou.

### 3. Ce que le diagnostic A15 valide

Le journal fourni valide, dans un perimetre borne:

* le KRW ClearSword et une ecriture reversible sur une page appartenant a
  l'application;
* l'identite `AGXAcceleratorG14P`, le GART et l'objet IOUAT en lecture;
* le buffer partage de 16 KiB, son zero initial et son empreinte V7;
* la mutation diagnostique de 32 octets et la restauration anticipee;
* la stabilite des snapshots apres restauration;
* la creation de la queue par selector 6;
* la creation et l'attachement de la notification par selectors 14 et 24;
* le preflight final `all-zero=yes`, `nonzero-count=0` avec l'empreinte de
  `BUFFER_INITIALIZED`;
* le nettoyage de la page, de la connexion et du service.

Le meme journal ne valide pas:

* un appel selector 25;
* une soumission de paquet non vide ou un traitement par MDSID;
* une callback firmware executee;
* la persistance d'un contexte GPU/RTKit;
* une fenetre physique generique;
* `krw_info.pte` ou `krw_info.kaddr`;
* `titan_run() == 0`;
* la publication de `titan_physwritebuf`;
* `physrw_pte_handoff()` ou une ecriture PTE;
* une ecriture protegee SPTM/PAPT.

## Conditions de publication de PHYSICAL_WRITE

### Publication directe dans Titan

`gPrimitives.physwritebuf = titan_physwritebuf` n'est execute que si:

1. `exploit_init()` a reussi a charger le flavor Titan;
2. `titan_init()` a accepte la cible;
3. `titan_run()` a retourne zero;
4. le chemin complet a atteint `titan_wait_for_self_ref_pte()` et a laisse
   `gTitanContext.krw_info.pte` non nul;
5. `gTitanContext.krw_info.kaddr` contient une fenetre exploitable.

Le critere de succes final dans `titan.m:3281-3284` est toutefois seulement
`gTitanContext.krw_info.pte != 0`. Il n'y a pas dans ce critere une preuve
explicite que la fenetre lit la bonne page physique, que le PTE est encore
valide apres le trigger, que le TLB est coheremment actualise ou que les
ressources GFX/RTKit restent vivantes.

### Contrat de `titan_physwritebuf`

`Titan/exploit/titan.m:3287-3310` decoupe la cible par pages de 16 KiB et
appelle `titan_map_page` pour chaque morceau. `titan_map_page`:

1. lit le PTE via `kread64`;
2. ecrit le PTE avec `kwrite64` pour faire pointer la fenetre vers `pa`;
3. appelle `kwritebuf` sur `krw_info.kaddr`;
4. restaure le PTE;
5. attend avant l'operation suivante.

Ce code depend donc d'un KRW encore actif, d'un PTE encore valide, d'une
fenetre encore mappee, d'une synchronisation correcte et de l'absence de
concurrence sur cette fenetre. Les retours de `kread64` et des deux
`kwrite64` de `titan_map_page` ne sont pas transformes en resultat d'erreur;
le seul retour verifie par `titan_physwritebuf` est celui de `kwritebuf` dans
le block. C'est une lacune de contrat a documenter, mais la corriger par une
nouvelle operation de verification runtime depasserait le perimetre de cette
revision.

La fonction est donc une implementation source-level de `PHYSICAL_WRITE`, pas
une capacite A15 runtime validee. La simple adresse du callback ne peut pas
promouvoir la capacite au-dela de `DECLARED` dans le ledger.

## Dependances GPU, firmware et fenetre memoire

Le chemin non borne de `titan_run()` exige au minimum:

* `titan_setup_command_buffers()` (`titan.m:2721-2792`), qui recherche un
  user client dans `backboardd`, copie un port IPC et cree puis soumet des
  buffers IOGPU;
* `titan_parse_RTKit_information()` (`titan.m:2795-2854`), avec lecture de
  l'IORVBAR et mapping de la page du reset vector;
* `titan_copy_gfx_firmware()` (`titan.m:2857-2905`);
* `titan_resolve_gfx_physical_addresses()` (`titan.m:2907-2934`);
* les mappings kernel GFX, `gfx_pf_run()`, `gfx_map_page()` et la construction
  des tables artificielles dans `titan_run()`;
* un thread d'attente qui observe l'installation du self-reference PTE
  (`titan_wait_for_self_ref_pte`, `titan.m:2936-2948`);
* le trigger `gfx_write32()` et une observation coherente du resultat
  (`titan.m:3258-3284`).

Le chemin A15ACTIVE est precisement construit pour ne pas atteindre ces
transitions. Les identites de vtables, objets, callbacks et pointeurs lus dans
les logs sont des observations d'identite. Elles ne constituent pas une preuve
de contexte firmware vivant ni de persistence d'une fenetre de mapping.

## Dependance avec `buildPhysRWPrimitive`

Sur A15, `DOJailbreaker.m:774-787` appelle
`libjailbreak_physrw_pte_init(false, 0)`, et non le chemin conventionnel
`libjailbreak_physrw_init(false)`.

Le handoff PTE (`BaseBin/libjailbreak/src/physrw_pte.c:150-195`) doit:

1. retrouver `proc`, `task`, `vm_map`, `pmap` et `ttep`;
2. etendre la plage de la table magique;
3. traduire l'entree PTE;
4. ecrire physiquement le PTE de la table magique;
5. traduire et ecrire la page contenant l'ASID;
6. publier l'adresse ASID et flusher le TLB.

Ces ecritures utilisent les wrappers `physwrite64()` de libjailbreak. Avant
publication du backend PTE, elles doivent donc disposer d'une primitive
physique utilisable, typiquement celle fournie par Titan si Titan avait
reellement etabli sa fenetre. Apres un handoff reussi,
`libjailbreak_physrw_pte_init` publie ses propres callbacks physiques et
efface les callbacks KRW directs (`physrw_pte.c:201-229`).

La relation est donc transitoire:

```text
Titan PHYSICAL_WRITE candidate
  -> prerequisite for the A15 PTE handoff
  -> physrw_pte publishes its own physical callbacks
  -> Titan is cleaned up
```

Le correctif V9 controle le resultat du handoff, conserve les callbacks
anterieurs en cas d'echec, detruit le mutex temporaire et ne commit `gAsid`
qu'apres succes. Cela ferme un defaut d'erreur, mais ne demontre ni la validite
de la fenetre, ni le succes d'une ecriture PTE, ni la compatibilite SPTM/PAPT.

Les wrappers de `primitives.c:108-314` distinguent les chemins KRW, physiques
et virtuels. Ils peuvent deriver une operation virtuelle depuis une primitive
physique, mais ne transforment pas un callback KRW en ecriture physique sans
`phystokv`; ils ne representent aucune capacite `PROTECTED_MEMORY_WRITE`.

## Matrice technique

| Etape | Prerequis | Etat A15 | Premiere preuve disponible | Blocage ou limite |
| --- | --- | --- | --- | --- |
| Selection kernel | Metadonnees et support exact | `PASS` metadata, runtime borne | Logs A15ACTIVE/diagnostic | Ne prouve pas la suite privilegiee |
| ClearSword KRW | `kreadbuf` / `kwritebuf` | `RUNTIME_VERIFIED`, borne | lecture Mach-O et self-page reversible | Pas une primitive physique/protegee |
| Translation | `vtophys` / `phystokv` installes | `DECLARED` / `NOT_TESTED` generique | initialisation libjailbreak | Aucun acces physique arbitraire observe |
| Titan target gate | A15 et build exact | `PASS` | `titan.target-gate` | Gate de recherche, pas succes d'exploit |
| Kernel context | proc/task/map/pmap/ttep lisibles | `PASS` borne | `titan.kernel-context` | Aucun handoff PTE execute |
| Patchfinder | Offsets AGX/GFX resolves | `PASS` | `titan.kernel-patchfinder` | Ne prouve pas leur usage runtime complet |
| AGX metadata | service/config/GART/IOUAT valides | `PASS` lecture | logs `agx-map-metadata` et `agx-gart-state` | Pas de mapping ou MMIO |
| Buffer AGX | buffer 16 KiB et baseline | `RUNTIME PASS` | V7 snapshots | Limite au buffer possede |
| Alias temporaire | mutation 32 octets et readback | `RUNTIME PASS` | `ALIAS_AFTER_WRITE` | Test reversible seulement |
| Restauration V7 | bytes originaux et baseline | `RUNTIME PASS` | `restore-before-preflight`, `ALIAS_AFTER_RESTORE` | Ne donne pas une primitive physique |
| Queue | selector 6 | `RUNTIME PASS` | `queue-created`, `queue-available` | Pas de soumission de paquet exploitable |
| Notification | selectors 14/24 | `RUNTIME PASS` | `notification-created`, `notification-bound` | Pas de callback firmware executee |
| Selector 25 | contrat packet/MDSID | `NOT_TESTED` par garde | `titan.zero-packet NOT_TESTED` | Desactive intentionnellement |
| User client/command buffers | port IPC, buffers et submits | `BLOCKED` dans le mode actif | arret avant `titan_setup_command_buffers` | Aucune preuve de contexte GPU |
| IORVBAR/RTKit | mapping et reset vector | `NOT_TESTED` ou `BLOCKED` | preflight read-only seulement | MMIO/RTKit actif desactive |
| Firmware GFX | copie, adresses physiques, patchfinder | `NOT_TESTED` | aucune execution A15 | Dependance GPU/firmware absente |
| Self-reference PTE Titan | ROP, trigger, observation | `NOT_TESTED` | aucun `titan.rop-result` | `krw_info.pte/kaddr` non demontres |
| `titan_run() == 0` | chaine complete et postcondition minimale | `BLOCKED` | `titan.run FAIL` | Retour volontaire avant la chaine complete |
| Titan callback | succes `titan_run()` | `NOT_PUBLISHED` sur les logs fournis | aucun `titan.physwrite.publish` PASS | Le point de publication n'est pas atteint |
| PTE handoff libjailbreak | PHYSICAL_WRITE utilisable et pmap valide | `NOT_TESTED` | aucun appel lance | Ecritures PTE et fenetre non prouvees |
| `PHYSICAL_WRITE` runtime | backend et postcondition | `BLOCKED` | aucune preuve | Ne pas deduire du pointeur source |
| Protected write | SPTM/PAPT contract | `NOT_TESTED` / `BLOCKED` | aucun appel | Aucun callback ordinaire ne le prouve |
| Cleanup/exploit lifetime | callbacks et contexte encore valides | cleanup borne `PASS` | `probe.cleanup` | La duree de vie d'une fenetre Titan complete reste non testee |
| Privileges/bootstrap | physrw postcondition | `NOT_REACHED` | diagnostics A15 | Depend du contrat physrw absent |

## Comparaison avec Dopamine officiel 3.x

La branche officielle `origin/3.x` locale (`448ff1a`) ne contient pas le
Titan A15 de cette branche privee. Son parcours PPL est un exploit selectionne
par metadonnees, suivi de la construction physrw et du bootstrap. Les points
reutilisables sont donc l'infrastructure, pas la preuve de compatibilite du
backend:

| Surface | Officiel 3.x | Branche privee A15 | Conclusion |
| --- | --- | --- | --- |
| Selection | `DOExploitManager` + support ranges | Meme infrastructure, Titan ajoute comme PPL | Reutilisable |
| Lifecycle | `load`, `run`, `cleanup`, active exploits | Meme contrat, avec chemin diagnostic separe | Reutilisable avec garde-fous |
| PPL result | Presume physwrite illimitee apres succes | Titan A15 retourne avant publication | Contrat non satisfait |
| AGX/RTKit | Pas de Titan A15 dans la branche officielle | Chaine Titan privee et versionnee | Adaptation propre a cette cible |
| Physrw A15 | PTE handoff apres PPL | Handoff jamais atteint en diagnostic | Bloque |
| Callback publication | Backend PPL puis physrw remplace les callbacks | Titan callback n'est jamais publie sur les logs | Non demontre |
| Cleanup | Avant elevation apres physrw | Cleanup borne du chemin diagnostic | Le lifetime complet reste non teste |
| SPTM/PAPT | Couvert par l'exploit officiel compatible | Aucun bypass A15 demontre | Bloque |

Le fait que le chemin officiel fonctionne sur certains A12/A13 ne transpose
ni ses offsets, ni son contrat PPL, ni ses garanties physrw a l'A15. Le code
prive lui-meme exclut la cible exacte du chemin normal via
`DOEnvironmentManager -isSupported` (`DOEnvironmentManager.m:800-821`).

## Premier prerequis non demontre

Le premier prerequis manquant n'est pas le symbole `buildPhysRWPrimitive` et
ce n'est plus la restauration du buffer AGX. C'est l'existence d'une
`PHYSICAL_WRITE` runtime valide et durable, avant le handoff PTE A15.

Plus precisement, il manque une preuve independante de la chaine suivante:

```text
contexte GPU/RTKit persistant
  -> fenetre self-reference PTE effectivement installee
  -> acces a la page physique cible et restauration du PTE
  -> retours d'erreur controles
  -> postcondition de lecture/ecriture autorisee
  -> callback physwrite utilisable par physrw_pte_handoff
```

Le diagnostic ne peut pas conclure que cette chaine est fausse materiellement;
il conclut seulement qu'elle n'est pas demontree et qu'elle est
intentionnellement inaccessible dans le mode actuel.

## Modifications V10

Aucune modification de code n'est justifiee par cette analyse:

* le garde-fou du selector 25 est conserve;
* les arrets MMIO/RTKit sont conserves;
* la publication Titan n'est pas forcee;
* le correctif V9 de `physrw_pte` reste en place;
* aucune nouvelle operation privilegiee ni nouvelle inference de capacite n'est
  ajoutee.

Le manque de verification interne de `titan_map_page` est une limite de
contrat a traiter dans une revision separee uniquement avec une strategie de
postcondition explicitement autorisee. Ajouter un appel ou promouvoir
automatiquement `PHYSICAL_WRITE` ici ferait exactement l'inference que cette
revision doit eviter et risquerait de casser les appareils officiellement
compatibles.

## Verification hors ligne

Les commandes prevues pour cette revision sont:

```text
python -m unittest discover -s tools/a15_ios26 -p "test_*.py"
python -m compileall -q tools/a15_ios26
python tools/a15_ios26/check_research_integration.py
git diff --check
```

La compilation Objective-C n'est pas modifiee par V10. La derniere
compilation reelle de `Titan.framework` a reussi dans GitHub Actions avec
Xcode 26.6 et le SDK installe iPhoneOS 26.5 via `-sdk iphoneos`, sur le commit
V9. Une nouvelle execution sur l'iPhone n'est pas requise et n'est pas lancee
pour ce rapport.

## Conclusion

ClearSword fournit le KRW borne necessaire aux observations actuelles. Titan
fournit une chaine AGX de diagnostic et une implementation source-level de
`titan_physwritebuf`, mais cette implementation n'a pas atteint son point de
publication et sa fenetre PTE n'a pas ete validee sur l'A15 cible.

La transition vers `PHYSICAL_WRITE` est donc bloquee par une dependance
runtime non demontree, puis par le handoff PTE lui-meme. La transition vers
`PROTECTED_MEMORY_WRITE`, l'elevation, le trust cache et le bootstrap restent
encore plus loin et ne doivent pas etre deduits de ces observations.

Ce rapport ne valide pas un jailbreak.

