#!/usr/bin/env bash
set -euo pipefail

# Offline random readable text generator
# Creates N files with pseudo-natural sentences.
# Defaults produce 4–8 sentences per file, 6–12 words per sentence.

# -------------------------- Defaults --------------------------
N=0
OUTDIR="random_texts"
PREFIX="file"
MIN_SENT=4
MAX_SENT=8
MIN_WORDS=6
MAX_WORDS=12
SEED=""

# -------------------------- Args ------------------------------
usage() {
  cat <<EOF
Usage: $0 -n <count> [options]

Required:
  -n, --number <count>        Number of files to generate

Options:
  -o, --outdir <dir>          Output directory (default: random_texts)
  -p, --prefix <name>         Filename prefix (default: file)
  --min-sent <N>              Min sentences per file (default: 4)
  --max-sent <N>              Max sentences per file (default: 8)
  --min-words <N>             Min words per sentence (default: 6)
  --max-words <N>             Max words per sentence (default: 12)
  --seed <int>                Optional RNG seed for reproducibility
  -h, --help                  Show this help

Examples:
  $0 -n 5
  $0 -n 10 -o texts --min-sent 3 --max-sent 6 --min-words 5 --max-words 10
  $0 -n 3 --seed 12345
EOF
}

# Simple long+short opt parser
while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--number)     N="${2:-}"; shift 2;;
    -o|--outdir)     OUTDIR="${2:-}"; shift 2;;
    -p|--prefix)     PREFIX="${2:-}"; shift 2;;
    --min-sent)      MIN_SENT="${2:-}"; shift 2;;
    --max-sent)      MAX_SENT="${2:-}"; shift 2;;
    --min-words)     MIN_WORDS="${2:-}"; shift 2;;
    --max-words)     MAX_WORDS="${2:-}"; shift 2;;
    --seed)          SEED="${2:-}"; shift 2;;
    -h|--help)       usage; exit 0;;
    *) echo "Unknown option: $1"; usage; exit 1;;
  esac
done

[[ "$N" =~ ^[0-9]+$ ]] && (( N > 0 )) || { echo "Error: -n/--number is required and > 0"; usage; exit 1; }
(( MIN_SENT <= MAX_SENT )) || { echo "Error: min-sent must be <= max-sent"; exit 1; }
(( MIN_WORDS <= MAX_WORDS )) || { echo "Error: min-words must be <= max-words"; exit 1; }

mkdir -p "$OUTDIR"

# -------------------------- RNG -------------------------------
# We try to use a reproducible RNG if --seed is given.
rand32() {
  if [[ -n "$SEED" ]]; then
    # xorshift32
    # shellcheck disable=SC2034
    SEED=$(( (SEED ^ (SEED << 13)) & 0xFFFFFFFF ))
    SEED=$(( (SEED ^ (SEED >> 17)) & 0xFFFFFFFF ))
    SEED=$(( (SEED ^ (SEED << 5))  & 0xFFFFFFFF ))
    printf '%u\n' "$SEED"
  else
    # Non-deterministic: read 4 bytes from /dev/urandom
    od -An -N4 -tu4 < /dev/urandom | tr -d ' '
  fi
}

rand_range() {
  # rand in [a, b]
  local a="$1" b="$2"
  local span=$(( b - a + 1 ))
  local r
  r=$(rand32)
  echo $(( a + (r % span) ))
}

# --------------------- Word source setup ----------------------
DICT_FILE="/usr/share/dict/words"
declare -a WORDS

if [[ -r "$DICT_FILE" ]]; then
  # Filter: lowercase alphabetic words, length 2..12
  mapfile -t WORDS < <(grep -E '^[a-z]+$' "$DICT_FILE" 2>/dev/null | awk 'length($0)>=2 && length($0)<=12' | head -n 50000)
fi

if (( ${#WORDS[@]} == 0 )); then
  # Fallback internal word list (offline, small but decent)
  read -r -d '' FALLBACK <<"EOT"
today,people,system,project,future,design,simple,random,forest,window,quiet,bright,signal,reason,pretty,minute,library,common,thread,update,lucky,choice,energy,coffee,summer,travel,record,device,buffer,packet,secret,bridge,river,castle,planet,story,chapter,memory,frank,almost,language,feature,stable,secure,gentle,modern,classic,hidden,silver,golden,ancient,softly,quickly,slowly,careful,mostly,rarely,always,never,perhaps,however,therefore,between,inside,against,without,within,around,toward,because,although,until,before,after,while,when,which,whose,these,those,other,every,each,first,second,third,small,large,heavy,light,early,late,fresh,clean,warm,cool,short,long,deep,sharp,plain,clear,smart,brave,quietly
EOT
  IFS=',' read -r -a WORDS <<< "$FALLBACK"
fi

WCOUNT=${#WORDS[@]}
(( WCOUNT > 0 )) || { echo "No words available."; exit 1; }

# --------------------- Sentence generator ---------------------
capitalize() {
  local s="$1"
  printf "%s%s" "${s:0:1}" | tr '[:lower:]' '[:upper:]'
  printf "%s" "${s:1}"
}

maybe_comma_insertion() {
  # With small probability, insert a comma before last 1-2 words
  local sentence="$1"
  local words
  IFS=' ' read -r -a words <<< "$sentence"
  local n=${#words[@]}
  if (( n > 6 )); then
    local roll
    roll=$(rand_range 1 100)
    if (( roll <= 20 )); then
      local pos=$(( n - $(rand_range 1 2) ))
      if (( pos > 1 && pos < n )); then
        words[$((pos-1))]="${words[$((pos-1))]},"
      fi
    fi
  fi
  printf "%s\n" "${words[*]}"
}

punctuation() {
  local roll
  roll=$(rand_range 1 100)
  if   (( roll <= 80 )); then echo "."
  elif (( roll <= 90 )); then echo "?"
  else                        echo "!"
  fi
}

gen_sentence() {
  local nwords
  nwords=$(rand_range "$MIN_WORDS" "$MAX_WORDS")

  local words=()
  for (( i=0; i<nwords; i++ )); do
    local idx
    idx=$(rand_range 0 $((WCOUNT-1)))
    words+=("${WORDS[$idx]}")
  done

  # Basic grammar spices: sprinkle "and", "the", "of", "to" occasionally
  local spice_roll
  spice_roll=$(rand_range 1 100)
  if (( spice_roll <= 35 && nwords > 6 )); then
    words[$((nwords/2))]="and"
  fi

  local s="${words[*]}"
  s=$(maybe_comma_insertion "$s")
  s="$(capitalize "${s%% *}") ${s#* }$(punctuation)"
  echo "$s"
}

gen_paragraph() {
  local nsent
  nsent=$(rand_range "$MIN_SENT" "$MAX_SENT")
  for (( k=0; k<nsent; k++ )); do
    gen_sentence
  done
}

# ------------------------- Main loop --------------------------
[[ -n "$SEED" ]] && SEED=$(( SEED & 0xFFFFFFFF ))

for (( f=1; f<=N; f++ )); do
  {
    # 1–3 paragraphs per file, blank line between
    local_paras=$(rand_range 1 3)
    for (( p=1; p<=local_paras; p++ )); do
      gen_paragraph
      (( p < local_paras )) && echo
    done
  } > "${OUTDIR}/${PREFIX}_${f}.txt"
  echo "Generated ${OUTDIR}/${PREFIX}_${f}.txt"
done

