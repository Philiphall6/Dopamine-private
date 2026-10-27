# A15 / iOS 26 : audit ciblé de la preuve d'exécution firmware V13

Target: `iPhone14,2`, Apple A15, iOS 26.0.1, build `23A355`.

Branch: `codex/a15-ios26-private-research`.

## Question auditée

Quels éléments indépendants permettraient de distinguer un selector 25 accepté
d'une commande MDSID réellement exécutée par GXF ?

Cet audit réutilise la V12, les journaux déjà fournis et les audits statiques
existants. Il ne soumet aucun paquet MDSID non vide, ne modifie pas Titan et
n'ajoute aucune opération MMIO, RTKit, TTBR0, physique, protégée ou bootstrap.

## Réponse courte

Le retour `kr=0x0` du selector 25, l'acceptation de l'enregistrement G14P de
`0x40` octets et le passage des compteurs `dispatch`/`command-index` de `0` à
`1` démontrent au mieux une acceptation et une progression observée du chemin
IOGPU côté hôte. Ils ne démontrent pas l'exécution du handler GXF.

Pour établir cette exécution, il faudrait au minimum deux observations
indépendantes et causalement corrélées :

1. une preuve de transport firmware pour le même envoi, telle qu'une transition
   de consommation ou une confirmation générée par le firmware ;
2. une preuve spécifique au handler GXF, telle qu'un effet ou un résultat
   attribuable uniquement au handler, avec un contrôle excluant l'activité
   hôte, le bookkeeping IOGPU et un événement retardé.

En l'absence de ces deux familles de preuves, l'état correct reste
`selector_25_accepted_no_gxf_execution_proof`.

## 1. Échelle de preuve

La distinction utile est la suivante :

| Niveau | Ce qui est établi | État actuel |
| --- | --- | --- |
| L0 — route statique | Le code contient une route MDSID vers un message GXF de `0x30` octets et un handler de type `0x0e` | `STATIC PASS` |
| L1 — acceptation hôte | Le wrapper G14P accepte un enregistrement `0x40` et le selector retourne `kr=0x0` | `RUNTIME PASS HISTORICAL` pour l'enregistrement vide |
| L2 — préparation IOGPU | Queue, notification, backend et états hôte atteignent les points attendus | `PARTIAL RUNTIME PASS` |
| L3 — transport firmware | Un événement firmware consomme ou confirme ce même envoi | `NOT_TESTED` |
| L4 — handler GXF | Un résultat causal propre au handler est observé | `NOT_TESTED` |
| L5 — primitive mémoire | Une fenêtre `PHYSICAL_WRITE` indépendante et ses postconditions sont validées | `BLOCKED` |

Le selector 25 ne doit être appelé « exécuté par GXF » qu'après L3 et L4.
L5 est une capacité différente et ne découle pas automatiquement de L4.

## 2. Ce que prouvent les observations disponibles

### 2.1 Retour du selector et taille de l'enregistrement

Le run historique a accepté un enregistrement G14P entièrement nul de `0x40`
octets et a retourné `kr=0x0`. L'audit du wrapper confirme aussi le contrat de
taille `0x40`, distinct du format générique `0x30`.

Cela prouve :

- que l'appel utilisateur a franchi les validations hôte observées ;
- que l'entrée a été traitée suffisamment loin pour retourner normalement ;
- que le résultat n'est pas l'erreur de prérequis notification `0xe00002bc`.

Cela ne prouve pas :

- que le parseur MDSID non vide a été appelé ;
- qu'un message GXF a été construit ou copié dans un anneau firmware ;
- que le firmware a consommé ce message ;
- que le handler de type `0x0e` a exécuté son store.

### 2.2 Compteurs `dispatch` et `command-index`

Les compteurs suivis dans le run historique sont passés de `0` à `1`, alors
que le reste de l'état observé est resté stable. C'est une observation utile
de progression du chemin IOGPU, mais son origine n'est pas suffisamment
indépendante : ces compteurs peuvent représenter le bookkeeping de la queue,
la consommation d'un enregistrement hôte ou une étape de dispatch avant le
firmware.

Ils constituent donc une preuve L1/L2, pas une preuve L3. Pour devenir une
preuve de transport firmware, il faudrait démontrer qu'ils sont écrits ou
avancés par le consommateur firmware, et corréler leur nouvelle valeur à un
identifiant unique de la même soumission.

### 2.3 Identité du firmware et des callbacks

Les lectures répétées du pointeur firmware, de sa vtable et des slots de
callback ont été stables. Elles établissent l'identité des objets et la
compatibilité avec l'image statique.

Elles ne constituent pas une invocation. Une adresse de callback stable peut
rester totalement inactive ; elle ne contient ni compteur d'appel, ni retour,
ni preuve d'effet.

### 2.4 Nettoyage et stabilisation

La fermeture de la connexion AGX et la libération du service ont réussi dans le
run borné. Le polling de snapshots a aussi observé un état stable.

Ces résultats montrent que le chemin hôte s'est nettoyé sans redémarrage. Ils
ne prouvent pas que le firmware a terminé une commande : une réponse tardive,
un backend encore vivant ou une ressource firmware indépendante ne sont pas
exclus par la seule fermeture hôte. La V12 marque donc le timing de libération
non vide comme inconnu.

## 3. Ce que la statique ajoute, et ce qu'elle n'ajoute pas

Les audits exact-image établissent une chaîne cohérente :

```text
IOGPU command 0x10002
  -> route d'envoi firmware
  -> entrée interne GXF de 0x30 octets
  -> type GXF 0x0e
  -> champs target/value/DSID
  -> store GXF vers une adresse basse
```

La liaison TTBR0 et l'instruction terminale `str w23, [x22]` sont des résultats
de contrôle de flux et de format sur les images 23A355. Ils ne sont pas des
traces d'exécution. En particulier, la statique ne fournit pas :

- la preuve qu'un appel utilisateur non vide atteint le parseur ;
- la preuve qu'un producteur appelable fabrique le message interne ;
- la preuve que le contexte GXF est réveillé et conserve son TTBR0 ;
- la preuve que le message est consommé plutôt que rejeté ou abandonné ;
- la preuve que `x22` pointe vers une page effectivement modifiée.

## 4. Audit du signal observable du pilote

Le pilote expose un candidat concret : la notification queue créée par le
selector 14. Le code de la branche demande 256 entrées de 32 octets, reçoit
une adresse utilisateur et un identifiant, puis vérifie la map et son objet
`IOGPUNotificationQueue`. Le selector 24 relie cette queue à la command queue
via `queue+0x428` et `queue+0x430`.

Ce candidat ne constitue toutefois pas encore une preuve indépendante :

- `titan_probe_notification_binding()` vérifie l'adresse, la protection, la
  longueur, la vtable et le lien de la map, mais ne lit pas les octets d'une
  entrée de notification après une soumission ;
- les snapshots `NOTIFICATION_BEFORE` et `NOTIFICATION_AFTER` portent sur le
  buffer AGX de travail, pas sur `output.address` de la notification queue ;
- `titan_capture_zero_packet_queue_state()` lit des champs de bookkeeping de
  la queue (`queue+0x520`), ainsi que `commandBuffer+0x28`, mais aucun de ces
  champs n'est établi comme écrit par le consommateur firmware ;
- `titan_wait_for_zero_packet_settle()` compare deux snapshots identiques dans
  une fenêtre de stabilisation. Cette égalité prouve la stabilité observée,
  pas l'auteur de la dernière écriture ;
- l'appel actif au selector 25 reçoit uniquement un code Mach et une sortie
  scalaire. Il ne reçoit pas de structure de completion firmware. Le wrapper
  générique de soumission passe lui aussi des sorties nulles.

La documentation locale du pilote établit donc l'existence d'un canal de
notification mappable, mais pas le format sémantique de ses entrées, leur
producteur, ni une relation vérifiée entre une entrée et le handler GXF.
Dans les données déjà collectées, aucune entrée de notification, aucun ack
firmware et aucun statut firmware corrélé à la soumission ne sont présents.

Le résultat de cet audit est ainsi :

```text
notification queue créée et liée       PASS runtime
map de notification identifiée         PASS runtime
entrée de notification lue             ABSENTE
producteur firmware de l'entrée        NON DÉMONTRÉ
ack/completion corrélé au selector 25  ABSENT
signal indépendant d'exécution GXF     NON DISPONIBLE
```

La queue de notification est le meilleur candidat documentaire pour une
future observation non destructive, mais elle ne peut pas être promue en
preuve tant que son contenu et sa provenance ne sont pas établis par une
analyse statique dédiée ou par une observation runtime séparée et autorisée.

## 5. Observateurs indépendants nécessaires

### A. Confirmation de transport firmware

Une preuve robuste devrait montrer, pour la même soumission :

- un identifiant ou une séquence unique associé à l'envoi ;
- une transition de producteur/consommateur ou un événement de notification
  produit après l'envoi ;
- un statut, code d'erreur ou accusé provenant d'un état firmware, et non la
  seule valeur de retour de `_IOConnectCallMethod` ;
- une fenêtre de quiescence qui exclut un événement retardé après le nettoyage.

Un compteur hôte sans provenance, un retour Mach nul ou une queue marquée
`ready=1` ne satisfont pas ces critères.

### B. Preuve spécifique du handler GXF

Même une confirmation de transport ne suffirait pas à prouver le handler
MDSID. Il faudrait en plus un effet qui ne puisse être produit que par le
handler sélectionné, avec :

- une précondition et une valeur initiale enregistrées ;
- un contrôle négatif qui parcourt le même chemin sans sélectionner ce handler ;
- une observation postérieure corrélée au même identifiant firmware ;
- l'exclusion des écritures hôte, AGX et des effets de nettoyage ;
- une vérification que l'effet est terminé avant la libération des ressources.

Une modification mémoire isolée ne suffirait pas si l'hôte ou AGX peut écrire
la même zone. Un accusé firmware sans effet spécifique ne suffirait pas non
plus à attribuer l'action au handler MDSID.

Cette section définit les critères d'analyse ; elle n'autorise pas la création
d'un paquet non vide ni une validation matérielle dans cette révision.

## 6. Matrice de la preuve actuelle

| Observateur | Résultat actuel | Interprétation correcte | Manque pour conclure GXF |
| --- | --- | --- | --- |
| `kr=0x0` selector 25 | Pass historique | Appel hôte accepté et revenu normalement | Origine firmware du résultat |
| Record G14P `0x40` | Pass statique/runtime vide | Contrat de taille et chemin d'acceptation | Parseur non vide |
| Notification 14/24 | Pass runtime | Prérequis de queue installé | Événement firmware corrélé |
| Queue `ready=1` | Pass runtime | État d'objet observé | Consommation firmware |
| `dispatch`/`command-index` `0→1` | Pass historique | Progression/bookkeeping observable | Provenance firmware |
| Pointeur/vtable firmware | Pass runtime | Identité stable | Invocation et retour |
| Route MDSID/GXF `0x30` | Pass statique | Route présente dans l'image | Producteur et consommation runtime |
| TTBR0 low-VA | Pass statique | Règle de traduction déduite | Contexte actif et store observé |
| Buffer inchangé | Pass runtime sur l'enregistrement vide | Aucun effet visible sur ce buffer | Résultat du handler non vide |
| Nettoyage AGX | Pass runtime borné | Ressources hôte fermées | Fin de traitement firmware |
| Notification/ack firmware | Absent | Aucun signal L3 disponible | Événement firmware indépendant |
| Effet handler MDSID | Absent | Aucun signal L4 disponible | Effet causal et contrôlé |

## 7. Conséquence pour `PHYSICAL_WRITE`

Une preuve L3/L4 GXF, si elle était obtenue séparément, démontrerait au mieux
une capacité d'écriture virtuelle dans le contexte GXF. Elle ne publierait pas
`PHYSICAL_WRITE` dans `libjailbreak` et ne démontrerait pas un contournement
SPTM/PAPT.

La transition vers `PHYSICAL_WRITE` exige encore les preuves décrites dans la
V10 : fenêtre physique durable, callbacks effectivement utilisables,
postconditions de lecture/écriture et validité du handoff PTE. La modification
V9 de gestion d'erreur protège cette transition contre les faux succès, mais
ne fournit aucune preuve runtime de la fenêtre.

La conclusion actuelle doit donc rester :

```text
selector 25 accepté                         PASS historique
activité IOGPU/queue                        PASS partiel
transport firmware causal                   NOT_TESTED
exécution du handler GXF                    NOT_TESTED
effet mémoire attribuable au handler        NOT_TESTED
PHYSICAL_WRITE                               BLOCKED
PROTECTED_MEMORY_WRITE                       BLOCKED
```

## 8. Conclusion

La différence décisive n'est pas un nouveau code de retour, mais la présence
d'un signal firmware indépendant et corrélé, suivie d'un effet spécifique au
handler et contrôlé. Les résultats disponibles franchissent L1 et une partie
de L2 ; ils ne franchissent pas L3 ni L4.

Il est donc techniquement incorrect de transformer le selector 25 historique
en preuve d'exécution GXF, et a fortiori en preuve de `PHYSICAL_WRITE` ou de
contournement SPTM. Le prochain jalon vérifiable est la conception d'un
observateur de confirmation firmware, pas l'activation d'un paquet MDSID non
vide sur l'iPhone.
