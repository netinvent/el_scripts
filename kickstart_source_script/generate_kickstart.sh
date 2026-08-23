#!/usr/bin/env bash

# Regenerates ks.el9-10.cfg from its template and the two scripts it embeds.
#
# The kickstart file carries verbatim copies of el_configurator.sh in its %post section and of
# kickstart_partition_creator.py in its %pre section. Keeping three files in step by hand does not
# hold: the committed kickstart had drifted twenty hunks behind the configurator, which meant every
# machine installed from it was missing fixes that had been in the repository for months.
#
# Usage:
#   generate_kickstart.sh                write the kickstart from the current sources
#   generate_kickstart.sh --check        report whether the committed kickstart is up to date,
#                                        without writing anything. Exits 1 when it is not.
#
# Paths can be overridden, which the pre-commit hook uses to build from staged content:
#   --template PATH  --el-configurator PATH  --partition-creator PATH  --output PATH

SCRIPT_DIR=$(cd "$(dirname "${0}")" && pwd)
REPO_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)

TEMPLATE="${SCRIPT_DIR}/ks.el9-10.cfg.in"
EL_CONFIGURATOR="${REPO_DIR}/el_configurator.sh"
PARTITION_CREATOR="${SCRIPT_DIR}/kickstart_partition_creator.py"
OUTPUT="${REPO_DIR}/ks.el9-10.cfg"
CHECK_ONLY=false

MARKER_PARTITION_CREATOR='@@KICKSTART_PARTITION_CREATOR@@'
MARKER_EL_CONFIGURATOR='@@EL_CONFIGURATOR@@'

fail() {
    printf 'generate_kickstart: %s\n' "${1}" >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "${1}" in
        --check)              CHECK_ONLY=true; shift ;;
        --template)           TEMPLATE="${2}"; shift 2 ;;
        --el-configurator)    EL_CONFIGURATOR="${2}"; shift 2 ;;
        --partition-creator)  PARTITION_CREATOR="${2}"; shift 2 ;;
        --output)             OUTPUT="${2}"; shift 2 ;;
        -h|--help)            sed -n '3,17p' "${0}"; exit 0 ;;
        *)                    fail "unknown argument '${1}'" ;;
    esac
done

for required in "${TEMPLATE}" "${EL_CONFIGURATOR}" "${PARTITION_CREATOR}"; do
    [ -f "${required}" ] || fail "missing input file '${required}'"
done

for marker in "${MARKER_PARTITION_CREATOR}" "${MARKER_EL_CONFIGURATOR}"; do
    count=$(grep -cxF -e "${marker}" -- "${TEMPLATE}")
    [ "${count}" -eq 1 ] || fail "template must contain exactly one ${marker} line, found ${count}"
done

generated=$(mktemp) || fail "cannot create a temporary file"
trap 'rm -f "${generated}"' EXIT

# Embeds a script, minus any trailing blank lines. Dropping those is what makes the generated file
# reproduce the hand built kickstart exactly, and keeps stray whitespace out of the %pre and %post
# sections when a source file happens to end with empty lines.
embed_script() {
    awk '
        { lines[NR] = $0 }
        END {
            last = NR
            while (last > 0 && lines[last] ~ /^[[:space:]]*$/) { last-- }
            for (i = 1; i <= last; i++) { print lines[i] }
        }
    ' "${1}"
}

# Substituting whole lines rather than using sed keeps the embedded scripts byte for byte identical
# to their sources: nothing in them is treated as a pattern or a replacement
while IFS= read -r line || [ -n "${line}" ]; do
    case "${line}" in
        "${MARKER_PARTITION_CREATOR}") embed_script "${PARTITION_CREATOR}" ;;
        "${MARKER_EL_CONFIGURATOR}")   embed_script "${EL_CONFIGURATOR}" ;;
        *)                             printf '%s\n' "${line}" ;;
    esac
done < "${TEMPLATE}" >> "${generated}"

# A half generated kickstart is worse than none: it would install a machine with a truncated %post.
# Refuse to emit anything unless both scripts really made it in and no marker survived.
for marker in "${MARKER_PARTITION_CREATOR}" "${MARKER_EL_CONFIGURATOR}"; do
    grep -qxF -e "${marker}" -- "${generated}" && fail "marker ${marker} was not substituted"
done
generated_lines=$(wc -l < "${generated}")
expected_lines=$(( $(wc -l < "${TEMPLATE}") + $(wc -l < "${PARTITION_CREATOR}") + $(wc -l < "${EL_CONFIGURATOR}") - 2 ))
# Trailing blank lines are dropped, so the result can be a little shorter, never longer
if [ "${generated_lines}" -gt "${expected_lines}" ] || [ "${generated_lines}" -lt $(( expected_lines - 20 )) ]; then
    fail "generated ${generated_lines} lines, expected about ${expected_lines}, refusing to write a partial kickstart"
fi

if [ "${CHECK_ONLY}" = true ]; then
    if [ ! -f "${OUTPUT}" ]; then
        printf 'generate_kickstart: %s does not exist, run %s to create it\n' "${OUTPUT}" "$(basename "${0}")" >&2
        exit 1
    fi
    if cmp -s "${generated}" "${OUTPUT}"; then
        printf 'generate_kickstart: %s is up to date\n' "$(basename "${OUTPUT}")"
        exit 0
    fi
    printf 'generate_kickstart: %s is out of date with the scripts it embeds\n' "$(basename "${OUTPUT}")" >&2
    printf '  regenerate it with: %s\n' "${SCRIPT_DIR#"${REPO_DIR}/"}/$(basename "${0}")" >&2
    diff -u "${OUTPUT}" "${generated}" | head -n 40 >&2
    exit 1
fi

if [ -f "${OUTPUT}" ] && cmp -s "${generated}" "${OUTPUT}"; then
    printf 'generate_kickstart: %s already up to date\n' "$(basename "${OUTPUT}")"
    exit 0
fi

cat -- "${generated}" > "${OUTPUT}" || fail "cannot write '${OUTPUT}'"
printf 'generate_kickstart: wrote %s (%s lines)\n' "$(basename "${OUTPUT}")" "$(wc -l < "${OUTPUT}")"
