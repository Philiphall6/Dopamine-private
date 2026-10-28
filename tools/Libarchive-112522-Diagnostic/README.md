# libarchive / CVE-2026-112522 — diagnostic iOS indépendant

Cette application est un banc de validation isolé pour iPhone14,2 sous iOS
26.0.1. Elle n'utilise pas Dopamine, ClearSword, Titan, IOKit, SPTM/PAPT ou
une primitive noyau.

Le dyld cache exact 23A355 exporte les symboles utilisés par le pont :
`archive_read_new`, `archive_read_support_filter_all`,
`archive_read_support_format_iso9660`, `archive_read_open_filename`,
`archive_read_next_header`, `archive_read_data_skip`, `archive_read_free`,
`archive_error_string`, `archive_entry_pathname_utf8` et
`archive_entry_size`. Les mêmes exports sont présents dans le composant
27.0.1 24A446. L'application vérifie leur présence à l'exécution et retourne
`LIBARCHIVE_UNAVAILABLE` sans poursuivre si l'interface n'est pas disponible.

## Ce que l'application fait

- charge explicitement `/usr/lib/libarchive.2.dylib` avec `dlopen` ;
- active le lecteur ISO9660 de libarchive ;
- traite une ISO9660/Joliet normale embarquée comme contrôle ;
- permet de choisir manuellement un fichier ISO depuis Fichiers ;
- n'intègre aucun fichier malformé et n'en génère aucun ;
- arme le test manuel une seule fois par installation ;
- écrit un journal JSONL avant, pendant et après l'appel à libarchive ;
- conserve un marqueur `TEST_INTERRUPTED` avant le traitement manuel afin de
  corréler une fermeture avec un éventuel rapport `.ips`.

Le contrôle normal est `CONTROL_ARCHIVE_PASS`. Les résultats manuels sont
`TEST_ARCHIVE_PASS`, `TEST_ARCHIVE_REJECTED` ou `TEST_ARCHIVE_ERROR`. Une
simple absence de réponse ne constitue jamais un crash confirmé.

## Compilation

Ouvrir `Libarchive-112522-Diagnostic.xcodeproj` avec Xcode 26.x et compiler la
cible `Libarchive-112522-Diagnostic` pour un iPhone. Le projet utilise
`IPHONEOS_DEPLOYMENT_TARGET=16.1` et `SDKROOT=iphoneos`.

Le workflow `.github/workflows/libarchive-112522-diagnostic.yml` effectue une
compilation non signée avec le SDK iPhoneOS installé par Xcode. Il ne lance
aucun fichier de test.

## Procédure manuelle unique

1. Installer l'application signée sur l'iPhone de test.
2. Lancer **Contrôle ISO normal** et vérifier `CONTROL_ARCHIVE_PASS`.
3. Exporter les journaux si le contrôle échoue.
4. Préparer séparément le fichier de référence autorisé pour l'essai manuel.
5. Utiliser **Choisir un ISO (manuel)** et confirmer une seule fois.
6. Ne pas relancer après une fermeture. Récupérer d'abord le journal et le
   rapport système.

Les journaux sont dans le conteneur de l'application :

```text
Documents/CVE-2026-112522.jsonl
Documents/CVE-2026-112522.state
```

## Récupération des rapports `.ips`

Les rapports système peuvent être récupérés via Réglages → Confidentialité et
sécurité → Analyse et améliorations → Données d'analyse, Xcode Devices and
Simulators ou Console.app avec l'iPhone connecté.

Le script `classify_crash.py` est hors ligne :

```text
python3 classify_crash.py --ips /chemin/rapport.ips \
  --log /chemin/CVE-2026-112522.jsonl
```

Un rapport n'est attribué à libarchive que s'il contient une référence de
module ou de pile correspondante. Le marqueur `TEST_INTERRUPTED` seul ne suffit
pas.

## Limites

Un crash de libarchive établirait une reproductibilité du chemin parser sur ce
build. Il ne démontrerait ni exécution de code arbitraire, ni lecture/écriture
noyau, ni écriture physique, ni contournement SPTM/PAPT.
