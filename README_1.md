# Analizator logów nginx (Bash)

Skrypt w Bashu analizujący log dostępu nginx (format `combined`). Liczy podstawowe
statystyki ruchu i wykrywa proste anomalie bezpieczeństwa wyłącznie narzędziami
z linii poleceń (`awk`, `grep`, `sort`, `uniq`) — bez żadnych zależności.

## Co robi

Sekcja ruchu:
- liczba żądań w rozbiciu na godziny
- rozkład kodów odpowiedzi HTTP
- ranking IP wg liczby żądań (top N)
- najczęstsze ścieżki zwracające 404

Sekcja bezpieczeństwa:
- **brute-force** — IP generujące dużo odpowiedzi 401/403 (próby logowania)
- **skanowanie** — IP generujące dużo odpowiedzi 404 (sondowanie ścieżek)
- **narzędzia atakujące** — ruch z charakterystycznym user-agentem (sqlmap, nikto, nmap, hydra, masscan)

Progi detekcji są konfigurowalne, żeby nie łapać przypadkowych pojedynczych błędów.

## Pliki

```
analyze.sh             właściwy analizator
access.log             przykładowy log do testów
generate_sample_log.py generator przykładowego logu (Python, seed 42)
```

Przykładowy log zawiera normalny ruch z trzema wplecionymi anomaliami, dzięki czemu
łatwo sprawdzić, że detekcja działa.

## Użycie

```bash
chmod +x analyze.sh
./analyze.sh access.log
```

Domyślnie analizuje `access.log` w bieżącym katalogu, można podać inną ścieżkę:

```bash
./analyze.sh /var/log/nginx/access.log
```

Progi i długość rankingów ustawia się zmiennymi środowiskowymi:

```bash
BRUTE_THRESHOLD=10 SCAN_THRESHOLD=20 TOP_N=15 ./analyze.sh access.log
```

| Zmienna           | Domyślnie | Znaczenie                                   |
|-------------------|-----------|---------------------------------------------|
| `BRUTE_THRESHOLD` | 20        | ile 401/403 z jednego IP = brute-force      |
| `SCAN_THRESHOLD`  | 30        | ile 404 z jednego IP = skanowanie           |
| `TOP_N`           | 10        | długość rankingów                           |

## Uruchamianie cyklicznie (cron)

Żeby raport leciał automatycznie co godzinę i dopisywał się do pliku:

```cron
0 * * * * /ścieżka/do/analyze.sh /var/log/nginx/access.log >> /ścieżka/do/raport.txt 2>&1
```

## Wygenerowanie świeżego przykładowego logu

```bash
python generate_sample_log.py
```

## Format logu nginx (combined)

```
IP - - [data:godzina] "METODA ścieżka HTTP/1.1" status rozmiar "referer" "user-agent"
```

Przy domyślnym dzieleniu po spacji: `$1` = IP, `$4` = data/godzina, `$7` = ścieżka,
`$9` = kod HTTP, na końcu user-agent.
