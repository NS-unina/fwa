# fwa nel benchmark (scan CLI)

Immagine `scanner/fwa` (`scanner/fwa/Dockerfile`): Ubuntu 20.04, l'ultima
release Ubuntu che pacchettizza `phantomjs` (usato dall'analyzer XSS), con
CPython 3.10 standalone installato da `uv` e le dipendenze di fwa installate da
`poetry.lock`. `tini` è il PID 1 e raccoglie i processi (`mitmdump`, web server
statico) che fwa lancia in background. Usarla soltanto contro l'ambiente di
laboratorio.

## Flusso

1. `wbe session scan.tool=fwa scan.strategy=<strategia>`
   (`adapters/scan_inputs.py`) seleziona le richieste del catalogo con i filtri
   `selection.*` (`keys`, `benchmark`, `case_id`, `vulnerability`, `location`,
   `query`, ...) e `lab.login`, e scrive un file HAR per ogni record (una
   richiesta, le classi di una policy e i suoi target), con `postData.params`
   per i body form, più `manifest-fwa.json`; vedi
   `scanner/strategies/README.md`. fwa sostituisce valori in query, body form, cookie,
   header, body JSON (chiavi top-level), body XML (elementi foglia con tag
   unico) e segmenti di path (identificati dall'indice in `path.split("/")`,
   scritto dall'adapter in `fwa_parameter`). Un payload che è un oggetto o
   array JSON (es. `{"$ne":null}`) va nel body JSON come valore JSON. I
   parametri `fragment` non viaggiano in HTTP e sono `unsupported`.
2. Per ogni record, `benchmark/fwa_scan.py` esegue la pipeline CLI di fwa in
   `<output>/<stem>/`:
   - `fwa record` + `fwa replay`: la richiesta passa dal proxy di registrazione
     e diventa la sessione valida (baseline) con la risposta reale;
   - `fwa fuzz --param <nome> --<location>` (`--querystring`, `--body`,
     `--cookies`, `--headers`, `--json`, `--xml`, `--path`): solo il valore del
     parametro etichettato, con i soli payload della classe (`classes.json`);
   - `fwa analyze` e `fwa oracle`: `observations.csv` e `vulnerabilities.csv`.
   Il verdetto del record è la regola della classe sulle osservazioni del
   parametro etichettato (`detected`, con i payload che l'hanno fatta scattare).

Un record senza osservazioni del parametro ha stato `not_attacked` e il
container esce con codice 1; i payload senza osservazione (es. una richiesta
andata in timeout) sono elencati in `unobserved_payloads`. Un errore di fwa
interrompe il run.

## Classi

`classes.json` è l'unica definizione: per ogni classe di
`ground_truth_injection.json` i tipi di `payloads.csv` usati e la regola
`fwa/oracle/<regola>.py` riportata.

| Classe | Tipi di payload | Regola: segnale |
| --- | --- | --- |
| `sqli` | `SQL`, `SQL_TIME_BASED` | `sql`: errore DBMS introdotto dal payload, HTTP 500 nuovo, risposta >5x, ritardo ≥4 s |
| `xss` | `XSS` | `xss`: `alert(41837)` eseguito da phantomjs |
| `html_injection` | `HTMLI` | `html_injection`: markup del payload riflesso non codificato |
| `cmdi` | `CMDI`, `CMDI_TIME_BASED`, `CMDI_OAST` | `cmdi`: output di `$((1873*7177))` o `/etc/passwd`, ritardo ≥4 s, interazione OAST |
| `path_traversal` | `LFI` | `lfi`: `root` e `sbin` nella risposta |
| `code_injection` | `CODE_INJECTION` | `code_injection`: risultato di `1873*7177` (assente dal payload) |
| `nosqli` | `NOSQL`, `NOSQL_TIME_BASED` | `nosqli`: errore MongoDB nuovo, HTTP 500 nuovo, risposta >5x, ritardo ≥4 s |
| `ssrf` | `SSRF`, `SSRF_OAST` | `ssrf`: `/etc/passwd` (`file://`) o pagina interna >5x; interazione OAST |
| `open_redirect` | `OPEN_REDIRECT` | `open_redirect`: 3xx con `Location` verso l'host del payload |

## OAST (Interactsh)

I tipi `SSRF_OAST` e `CMDI_OAST` di `payloads.csv` contengono il segnaposto
`{oast}`. Per ogni target con payload di questi tipi il driver avvia
`interactsh-client` (nell'immagine, versione e SHA-256 fissati) verso
`--interactsh-server` (`oast.server`, per default il servizio
`oast` del laboratorio, `http://oast.lab`), che registra un dominio
`<id>.oast.lab` per ogni payload: ogni payload ha il suo, quindi
un'interazione identifica la richiesta che l'ha causata. Dopo il fuzzing il
driver attende due periodi di polling (`--interactsh-poll-seconds`, default 5
come il client), ferma il client e passa le interazioni ad `analyze`
(`FWA_OAST_INTERACTIONS`): l'analyzer `oast_interaction` segna i payload il cui
dominio è stato contattato (DNS, HTTP o SMTP), e le regole `ssrf` e `cmdi` li
riportano. Ogni target registra `oast` (payload, interazioni, attesa). Senza
`--interactsh-server` una classe con payload OAST è un errore.

## Ordine dei payload e early stop

Due opzioni indipendenti di `fwa fuzz` (e di `fwa_scan.py`), da `wbe session` con
`scan.simple_payloads_first=true` e `scan.early_stop=true`; `run.json` le registra
(`simple_payloads_first`, `early_stop`).

### `--simple-payloads-first`

Senza l'opzione i payload vengono inviati nell'ordine di `payloads.csv`. Con
l'opzione l'ordine è: tier, poi `Level`, poi ordine del file.

- Tier, dal tipo: prima i payload con evidenza nella risposta, poi i
  time-based (`*_TIME_BASED`), infine gli out-of-band (`*_OAST`).
- `Level` (colonna di `payloads.csv`): `1` il payload da solo, senza un
  contesto da chiudere (es. `'`, `1 OR 1=1`, `<script>…`, `;echo …`,
  `/etc/passwd`, `http://localhost/`); `2` chiude prima il contesto in cui è
  iniettato (apici, tag, commenti, terminatori di istruzione); `3` evade un
  filtro o usa una rappresentazione alternativa (case, nesting, encoding, null
  byte, grafie dell'IP, URL protocol-relative, offuscamento).

Senza `--early-stop` cambia solo l'ordine di invio (`request_index` e
`seconds` delle detection), non l'insieme dei payload inviati.

### `--early-stop`

fwa analizza ogni risposta appena il proxy di registrazione la registra, con
gli stessi analyzer e le stesse regole di `analyze` e `oracle` sulla stessa
entry HAR. Quando una regola rileva una vulnerabilità in un punto di iniezione
(richiesta, location, parametro), fwa non invia i payload rimanenti di quel
punto dei tipi giudicati dalla regola (`PAYLOAD_TYPES` di
`fwa/oracle/<regola>.py`); le altre classi del record continuano. I payload
vengono inviati in ordine, uno alla volta (`--threads 1`): il numero di
payload risparmiati dipende dall'ordine.

Ogni target riporta `early_stop`: gli `stops` (regola e payload che hanno
fermato la classe) e gli `skipped_payloads` (non inviati, esclusi da
`unobserved_payloads`); `run.json` riporta, per record, `skipped_payloads`.
`analyze` e `oracle` girano comunque dopo il fuzzing sulle richieste inviate:
ogni stop deve essere anche una loro detection, altrimenti il run si
interrompe con un errore. Le interazioni OAST arrivano solo dopo il fuzzing,
quindi non fermano mai una classe; l'analisi online (phantomjs per l'XSS
compreso) è inclusa in `duration_seconds`.

## Uso

```bash
uv run wbe session scan.tool=fwa scan.strategy=scanner/strategies/gold_strategy.json
uv run wbe session scan.tool=fwa scan.strategy=scanner/strategies/all_scanners_per_url.json selection.benchmark=port-swigger
uv run wbe session scan.tool=fwa scan.strategy=scanner/strategies/gold_strategy.json scan.early_stop=true scan.simple_payloads_first=true
```

L'output contiene un JSON per record e `run.json` (versioni di fwa,
mitmproxy e phantomjs, SHA-256 di `payloads.csv`, analyzer, classi, durata e
costo totali, record `unsupported`).

Il costo di un record (`cost`) conta le richieste registrate dal proxy di fwa,
cioè quelle con risposta: `payloads_sent` sono le richieste di fuzzing (una per
payload e target), `http_requests` anche la baseline, `duration_seconds` il
tempo del record, `analyze` e `oracle` compresi. `cost.by_class` riporta, per
ogni classe, le richieste di fuzzing dei suoi tipi di payload e la somma dei
loro tempi di risposta. `run.json` somma i contatori in `cost` e riporta in
`duration_seconds` la durata dell'intero run.

Ogni target riporta richieste e tempi di risposta per tipo di payload
(`fuzz_by_payload_type`) e le richieste il cui payload fwa non attribuisce al
parametro (`unattributed_fuzz_requests`). Ogni detection riporta la richiesta
del suo payload in `fuzz.har`: `request_index` è la posizione nel record (1 è la
baseline, poi le richieste di fuzzing dei target nell'ordine di invio: fwa fuzz
usa un solo thread) e `seconds` il tempo dall'inizio del record alla risposta.
Senza `--early-stop` fwa riconosce la vulnerabilità solo dopo tutto il fuzzing,
con `analyze` e `oracle`: la richiesta è quella in cui l'evidenza era
disponibile.

Le predizioni si ottengono da questo output con il convertitore `driver/fwa`
(`wbe predictions`), vedi `scanner/strategies/README.md`.

## Limiti

- Un'osservazione confronta una risposta fuzz con la sola baseline: i
  differenziali booleani (vero/falso) non sono esprimibili, quindi SQLi/NoSQLi
  boolean-blind senza errori né ritardi non vengono rilevate.
- phantomjs carica la risposta da `127.0.0.1:18081/xss.html` e non interagisce
  con la pagina: XSS che richiedono un click (`javascript:` in un link) o un
  DOM sink alimentato da script esterni non vengono eseguite.
- SSRF blind e i casi stored che richiedono una seconda richiesta non sono
  coperti.
- Un valore JSON viene sostituito per intero: un'injection dentro un documento
  strutturato (es. una stringa di una query GraphQL nel campo `query`) rompe
  la sintassi del documento prima di raggiungere il sink.
