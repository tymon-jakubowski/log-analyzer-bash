#!/usr/bin/env bash
#
# analyze.sh - analizator logow dostepu nginx (format "combined")
#
# Liczy podstawowe statystyki ruchu i wykrywa proste anomalie bezpieczenstwa:
# brute-force, skanowanie sciezek oraz ruch od znanych narzedzi atakujacych.
#
# Uzycie:
#   ./analyze.sh [sciezka_do_logu]
#   (domyslnie analizuje plik access.log w biezacym katalogu)
#
# Konfigurowalne progi (mozna nadpisac zmiennymi srodowiskowymi):
#   BRUTE_THRESHOLD - ile odpowiedzi 401/403 z jednego IP traktujemy jak brute-force
#   SCAN_THRESHOLD  - ile odpowiedzi 404 z jednego IP traktujemy jak skanowanie
#   TOP_N           - dlugosc rankingow (top IP, top 404 itd.)
#
# Przyklad: BRUTE_THRESHOLD=10 ./analyze.sh /var/log/nginx/access.log
#
# Format linii logu (pola rozdzielone spacja):
#   $1  = adres IP
#   $4  = [data:godzina:minuta:sekunda
#   $7  = zadana sciezka
#   $9  = kod odpowiedzi HTTP
#   na koncu, w cudzyslowie: user-agent
# ---------------------------------------------------------------------------

set -euo pipefail

# --- konfiguracja ----------------------------------------------------------
LOG="${1:-access.log}"
BRUTE_THRESHOLD="${BRUTE_THRESHOLD:-20}"
SCAN_THRESHOLD="${SCAN_THRESHOLD:-30}"
TOP_N="${TOP_N:-10}"

# --- walidacja wejscia -----------------------------------------------------
if [[ ! -f "$LOG" ]]; then
    echo "Blad: nie znaleziono pliku logu: $LOG" >&2
    echo "Uzycie: $0 [sciezka_do_logu]" >&2
    exit 1
fi

# Pomocnik: wypisuje wejscie ze stdin, a jesli jest puste - "(brak)".
print_or_none() {
    local out
    out="$(cat)"
    if [[ -z "$out" ]]; then
        echo "  (brak)"
    else
        echo "$out"
    fi
}

# --- naglowek raportu ------------------------------------------------------
echo "==========================================================="
echo " Raport analizy logu nginx"
echo " Plik:        $LOG"
echo " Wygenerowano $(date '+%Y-%m-%d %H:%M:%S')"
echo " Liczba zadan $(wc -l < "$LOG")"
echo "==========================================================="

# === 1. RUCH WG GODZIN =====================================================
# Z pola $4 ([10/Mar/2024:14:...]) wycinamy godzine dzielac po ":".
echo
echo "--- Ruch wg godzin ---"
awk '{ split($4, t, ":"); print t[2] }' "$LOG" \
    | sort | uniq -c | sort -k2 -n \
    | awk '{ printf "  %s:00   %s zadan\n", $2, $1 }'

# === 2. ROZKLAD KODOW HTTP =================================================
echo
echo "--- Rozklad kodow HTTP ---"
awk '{ print $9 }' "$LOG" | sort | uniq -c | sort -rn \
    | awk '{ printf "  %-5s %s\n", $2, $1 }'

# === 3. TOP IP =============================================================
echo
echo "--- Top $TOP_N IP (liczba zadan) ---"
awk '{ print $1 }' "$LOG" | sort | uniq -c | sort -rn | head -n "$TOP_N" \
    | awk '{ printf "  %-16s %s\n", $2, $1 }'

# === 4. NAJCZESTSZE 404 ====================================================
echo
echo "--- Najczestsze sciezki z kodem 404 ---"
awk '$9 == 404 { print $7 }' "$LOG" | sort | uniq -c | sort -rn | head -n "$TOP_N" \
    | awk '{ printf "  %-30s %s\n", $2, $1 }' | print_or_none

# ===========================================================================
#  SEKCJA BEZPIECZENSTWA
# ===========================================================================
echo
echo "==========================================================="
echo " BEZPIECZENSTWO"
echo "==========================================================="

# === 5. BRUTE-FORCE: duzo 401/403 z jednego IP =============================
echo
echo "--- Mozliwy brute-force (>= $BRUTE_THRESHOLD odpowiedzi 401/403 z jednego IP) ---"
awk '$9 == 401 || $9 == 403 { print $1 }' "$LOG" \
    | sort | uniq -c | sort -rn \
    | awk -v prog="$BRUTE_THRESHOLD" \
        '$1 >= prog { printf "  IP %-16s %s odpowiedzi 401/403\n", $2, $1 }' \
    | print_or_none

# === 6. SKANOWANIE: duzo 404 z jednego IP ==================================
echo
echo "--- Mozliwe skanowanie (>= $SCAN_THRESHOLD odpowiedzi 404 z jednego IP) ---"
awk '$9 == 404 { print $1 }' "$LOG" \
    | sort | uniq -c | sort -rn \
    | awk -v prog="$SCAN_THRESHOLD" \
        '$1 >= prog { printf "  IP %-16s %s zadan 404\n", $2, $1 }' \
    | print_or_none

# === 7. NARZEDZIA ATAKUJACE: po polu user-agent ============================
echo
echo "--- Ruch od znanych narzedzi (sqlmap / nikto / nmap / hydra / masscan) ---"
grep -iE 'sqlmap|nikto|nmap|hydra|masscan' "$LOG" \
    | awk '{ print $1 }' | sort | uniq -c | sort -rn \
    | awk '{ printf "  IP %-16s %s zadan\n", $2, $1 }' | print_or_none

echo
echo "=== Koniec raportu ==="
