# A15 / iOS 26.0.1 : corrélation AGX → GXF — V16

Target : `iPhone14,2`, Apple A15, iOS 26.0.1, build `23A355`.

Branche : `codex/a15-ios26-private-research`.

Cette révision est documentaire. Elle ne construit ni ne soumet de paquet,
n'active pas le selector 25, ne modifie pas Titan, TTBR0, SPTM/PAPT ou les
protections mémoire, et ne lance pas de test sur l'iPhone.

## Conclusion exécutive

Les preuves disponibles ne permettent toujours pas de distinguer une
commande MDSID réellement exécutée par GXF d'une requête IOGPU acceptée.

L'ancien essai du commit `a91336d4f2a3e3ae9dd52d2bc43b72e852f39c87` établit
les faits suivants :

- le selector 25 a accepté une requête liée avec `kr=0x0` ;
- les compteurs hôte `dispatch` et `command-index` sont passés de `0` à `1` ;
- la connexion et le service ont été nettoyés ;
- le record était entièrement nul et mesurait `0x40` octets.

Ces faits ne constituent pas une confirmation GXF. L'audit exact-image indique
que l'en-tête nul sélectionne le chemin empty-record et évite le dispatch de
commande non vide. Le retour Mach, les compteurs de queue et la libération de
la connexion sont donc des observations d'acceptation et de bookkeeping
IOGPU/AGX, pas un accusé d'exécution du firmware.

V15 a ajouté la seule observation passive qui manquait à V14 : la capture de
la map de notification. Sur le run fourni, la map de `0x2454` octets garde la
même empreinte après création, après liaison, après délai et avant libération,
avec `changed-bytes=0` et aucune plage modifiée. Mais V15 désactive le selector
25 ; cette stabilité montre l'absence d'un événement spontané pendant le
cycle de vie de la queue, pas le résultat d'une commande firmware.

Verdict actuel :

```text
IOGPU_READY                  PASS runtime
IOGPU_BOUND                  PASS runtime
selector 25 accepté         PASS historique
bookkeeping dispatch        PASS historique, attribution hôte non firmware
map notification modifiée   NON OBSERVÉE dans V15
événement pilote attribué   NON DÉMONTRÉ
événement firmware attribué NON DISPONIBLE
exécution GXF corrélée      NOT_TESTED
PHYSICAL_WRITE              BLOCKED
PROTECTED_MEMORY_WRITE      BLOCKED
```

## 1. Comparaison V15 / ancien selector 25

### Ancien run `a91336d`

Le rapport `docs/A15_IOS26_EMPTY_RECORD_ACCEPTED_V3_2026_10_20.md` décrit un
unique run sur `23A355` :

| Observation | Résultat | Portée exacte |
| --- | --- | --- |
| Client et buffer AGX | PASS | identité et stabilité des objets suivis |
| Queue de commande | PASS | queue possédée et liée au même client |
| Queue de notification | PASS | selector 14 puis selector 24 |
| Record selector 25 | `kr=0x0` | record nul de `0x40` octets |
| `dispatch` | `0 → 1` | bookkeeping de la queue observée après l'appel |
| `command-index` | `0 → 1` | bookkeeping associé à la soumission |
| Pool/backend détaillé | inchangé | aucune preuve d'un effet firmware |
| Notification map | non capturée | aucune ancienne capture à réutiliser |
| Nettoyage connexion/service | PASS | fermeture du client et libération du service |

La source historique ne contient pas de capture passive de la zone de
notification. Les recherches dans les artefacts disponibles ne retrouvent pas
de journal historique décrivant une entrée, un index producteur/consommateur,
un code d'événement ou un timestamp firmware. Ces informations ne sont pas
inventées dans ce rapport.

### Run V15 fourni

Le run V15 réutilise la création et la liaison mais s'arrête avant toute
soumission :

| Point de capture | Map | Résultat |
| --- | ---: | --- |
| `AFTER_CREATE` | `0x2454` | `changed-bytes=0`, empreinte initiale établie |
| `AFTER_BIND` | `0x2454` | même empreinte, aucune plage modifiée |
| `AFTER_DELAY` | `0x2454` | même empreinte, aucune plage modifiée |
| `BEFORE_RELEASE` | `0x2454` | même empreinte, aucune plage modifiée |

Le `baseline-match=no` de `AFTER_CREATE` correspond à l'établissement de la
référence par la première capture ; les captures suivantes indiquent bien
`baseline-match=yes`. Il ne signale pas une mutation de la map.

V15 ajoute également un contrôle Metal ordinaire indépendant : `status=4`,
`completed=yes` et `contents-match=yes`. Ce contrôle valide le chemin GPU
public de Metal, mais ne traverse ni le client IOGPU expérimental ni le chemin
MDSID/GXF ; il ne peut donc pas servir de contrôle positif firmware pour
selector 25.

## 2. Ce que les sources établissent

L'audit de la frontière de soumission établit statiquement :

- le contrat G14P du record externe est de `0x40` octets ;
- le chemin lié nécessite un objet de notification à `queue+0x428` ;
- un en-tête de commande nul sélectionne le chemin empty-record ;
- le chemin empty-record évite le dispatch de commande non vide ;
- le nettoyage backend est attendu sur le chemin normal, mais sa réalisation
  complète n'est pas directement observée par le run historique.

L'analyse firmware établit séparément une route MDSID/GXF et une géométrie de
traduction low-VA/TTBR0. Elle ne fournit pas pour autant une causalité
runtime : aucun record MDSID non vide n'a été envoyé et aucun effet spécifique
du handler GXF n'a été observé.

Les analyses de handoff GXF identifient des écritures de compteurs et d'états
dans des structures internes de handoff. Elles ne prouvent pas que ces champs
se trouvent dans la map utilisateur `IOGPUNotificationQueue`, ni qu'ils sont
publiés comme notifications du record selector 25. Il serait incorrect de
les utiliser comme format de notification sans une chaîne de références
exacte et une observation runtime bornée.

## 3. Contrat de notification : informations absentes

Les wrappers et headers examinés exposent le contrat de création et de liaison,
pas la sémantique des octets retournés :

| Information nécessaire | Disponible ? | Pourquoi cela compte |
| --- | --- | --- |
| Adresse et longueur de map | Oui | permet des lectures bornées |
| Nombre et taille demandés | Oui (`256 × 32`) | contrat d'appel seulement |
| Layout d'une entrée | Non | impossible de décoder un événement |
| Index producteur/consommateur | Non | impossible de distinguer queue vide et queue consommée |
| Producteur firmware identifié | Non | une mutation brute reste ambiguë |
| Identifiant de soumission associé | Non | pas de corrélation univoque |
| Code de completion documenté | Non | `kr=0` n'est pas une completion GXF |
| Timestamp ou séquence firmware | Non | pas d'ordre causal indépendant |
| API de lecture/ack côté hôte | Non | pas de confirmation de consommation |

La longueur observée `0x2454` ne définit donc pas le format d'une entrée. De
même, la capacité de payload historique `0x2000` ne doit pas être assimilée à
une structure de notification ou à un compteur firmware.

## 4. Niveaux de preuve et critères indépendants

Pour passer d'un niveau au suivant, il faudrait des critères distincts :

1. **Requête acceptée par IOGPU** : retour normal de l'external method et
   contrat de longueur accepté. Le run historique satisfait ce niveau.
2. **Soumission enregistrée par le chemin AGX** : progression d'un état de
   queue dont le producteur est attribué au code hôte/IOGPU. `dispatch` et
   `command-index` peuvent documenter ce niveau, mais pas le firmware.
3. **Backend préparé** : identité et durée de vie d'un objet backend observées
   avant/après l'appel, avec libération vérifiée. Le run historique ne fournit
   pas cette preuve complète.
4. **Parser GXF atteint** : trace ou effet borné montrant que le chemin non vide
   a dépassé le framing IOGPU et le dispatch de commande. Le record nul ne
   suffit pas ; l'analyse statique dit même que son parser de commande est
   contourné.
5. **Événement firmware** : une entrée de notification dont le format et le
   producteur firmware sont démontrés, reliée à un identifiant de soumission
   unique et indépendante du retour Mach et du bookkeeping hôte.
6. **Exécution GXF** : en plus de l'événement précédent, une postcondition
   spécifique au handler GXF, avec contrôle négatif, stabilité temporelle et
   nettoyage vérifié.

Un changement d'octets, un compteur `0 → 1`, une vtable stable ou `kr=0` ne
satisfait pas les niveaux 5 et 6.

## 5. Évaluation de l'instrumentation passive V15

L'instrumentation existante est suffisante pour établir l'absence de mutation
spontanée pendant la création, la liaison et l'attente courte :

- les bornes de la map sont revalidées avant chaque capture ;
- la taille lue reste limitée à `0x2454` ;
- les empreintes, octets modifiés et plages sont comparés ;
- la capture pré-libération précède `munlock`, `IOServiceClose` et la
  libération du service ;
- le selector 25 reste explicitement désactivé ;
- le nettoyage et l'arrêt contrôlé restent inchangés.

Ajouter davantage de hashes ou de délais sans connaître le format du message
n'apporterait pas une preuve nouvelle : cela ne ferait que raffiner le niveau
`NOTIFICATION_CHANGED`, qui n'est pas équivalent à un événement firmware.
V16 ne modifie donc pas le code de production et n'ajoute pas de test appareil.

## 6. Prochaine action vérifiable

La prochaine action utile est hors ligne : fermer la question de provenance
dans l'image exacte 23A355 en recherchant une chaîne complète, de la création
de l'entrée jusqu'à sa publication dans la map utilisateur :

1. identifier le code qui écrit effectivement dans la map de notification ;
2. établir si le producteur est IOGPU, AGX, RTBuddy ou GXF ;
3. récupérer le layout, les index et tout identifiant de fence/commande ;
4. relier cette écriture à un callback ou à un message firmware démontré ;
5. ajouter seulement des assertions passives si ces références sont toutes
   fermées.

Si cette chaîne n'existe pas dans les sources accessibles, la queue doit être
classée comme surface d'observation non probante pour ce diagnostic. Il n'y a
alors aucune expérience appareil non destructive justifiée sous les garde-fous
actuels : le prochain essai exigerait une nouvelle soumission, ce qui est
explicitement hors périmètre V16.

## 7. Limites et décision

Le succès historique du selector 25 est un résultat de transport/acceptation
d'un record vide. Il ne démontre ni traitement d'un MDSID non vide, ni
exécution GXF, ni résolution low-VA effective, ni écriture physique ou
protégée.

Le run V15 apporte une observation utile mais négative : aucune notification
spontanée n'est apparue lorsque la queue a été créée et liée sans soumission.
Il ne permet pas d'inférer le comportement post-soumission.

Décision V16 :

```text
preuve nouvelle apportée par V15       stabilité passive de la map
distinction acceptation/exécution      toujours impossible
signal de completion exploitable        non identifié
amélioration production justifiée       non
nouvelle expérience appareil            non autorisée / non justifiée
état PHYSICAL_WRITE                     BLOCKED
état PROTECTED_MEMORY_WRITE             BLOCKED
```

## Sources locales

- `Application/Dopamine/Exploits/Titan/exploit/IOGPUDevice.h`
- `Application/Dopamine/Exploits/Titan/exploit/IOGPUDevice.c`
- `Application/Dopamine/Exploits/Titan/exploit/titan.m`
- `docs/A15_IOS26_EMPTY_RECORD_ACCEPTED_V3_2026_10_20.md`
- `docs/A15_IOS26_AGX_NOTIFICATION_EVIDENCE_V14.md`
- `docs/A15_IOS26_AGX_NOTIFICATION_BINDING_V1_2026_10_20.md`
- `docs/A15_IOS26_AGX_ZERO_PACKET_ABI_V3_2026_10_20.md`
- `docs/A15_IOS26_MDSID_READINESS_NO_GO_2026_10_20.md`
- `docs/A15_IOS26_OFFLINE_FUNCTIONAL_PATH_2026_10_19.md`
- `tools/a15_ios26/audit_agx_submit_boundary.py`
- `tools/a15_ios26/audit_mdsid_ttbr0_binding.py`
- `tools/a15_ios26/analyze_agx_uppl_producer.py`
- `tools/a15_ios26/test_agx_notification_passive_v15.py`
- `tools/a15_ios26/mdsid_gxf_transition_model.py`
