#!/bin/bash

BYTES=128
PID=$(pgrep sigdream)

if [ -z "$PID" ]; then
    echo "error: no sigdream process found"
    exit 1
fi

if [ ! -d "/proc/$PID" ]; then
    echo "error: process $PID not found"
    exit 1
fi

echo "========================================"
echo "pid: $PID"
echo "========================================"
echo

dump_region() {
    local name="$1"
    local pattern="$2"
    local alt_pattern="$3"

    local info=$(grep -E "$pattern" /proc/$PID/maps | head -1)

    if [ -z "$info" ] && [ -n "$alt_pattern" ]; then
        info=$(grep -E "$alt_pattern" /proc/$PID/maps | head -1)
    fi

    if [ -z "$info" ]; then
        echo "[$name] not found"
        echo
        return
    fi

    local perms=$(echo $info | awk '{print $2}')
    local start_addr=$(echo $info | cut -d' ' -f1 | cut -d'-' -f1)
    local end_addr=$(echo $info | cut -d' ' -f1 | cut -d'-' -f2)
    local start_dec=$((0x$start_addr))
    local end_dec=$((0x$end_addr))
    local size=$((end_dec - start_dec))
    local dump_size=$((BYTES > size ? size : BYTES))

    echo "[$name]"
    echo "  address: 0x$start_addr - 0x$end_addr"
    echo "  perms:   $perms"
    echo "  size:    $size bytes"
    echo "  dumping: $dump_size bytes"
    echo

    dd if=/proc/$PID/mem bs=1 count=$dump_size skip=$start_dec 2>/dev/null | \
    hexdump -C | head -n $((dump_size / 16 + 1))

    echo
}

echo "--- ELF HEADER ---"
dump_region "elf" '.*r--p 00000000.*sigdream$' '.*rw-p 00000000.*sigdream$'

echo "--- TEXT SECTION ---"
dump_region "text" '.*r-xp.*sigdream$' '.*rw-p.*sigdream$'

echo "--- HEAP ---"
HEAP_INFO=$(grep '\[heap\]' /proc/$PID/maps)
if [ -n "$HEAP_INFO" ]; then
    START_ADDR=$(echo $HEAP_INFO | cut -d' ' -f1 | cut -d'-' -f1)
    END_ADDR=$(echo $HEAP_INFO | cut -d' ' -f1 | cut -d'-' -f2)
    PERMS=$(echo $HEAP_INFO | awk '{print $2}')
    START_DEC=$((0x$START_ADDR))
    END_DEC=$((0x$END_ADDR))
    SIZE=$((END_DEC - START_DEC))
    DUMP_SIZE=$((BYTES > SIZE ? SIZE : BYTES))

    echo "  address: 0x$START_ADDR - 0x$END_ADDR"
    echo "  perms:   $PERMS"
    echo "  size:    $SIZE bytes"
    echo "  dumping: $DUMP_SIZE bytes"
    echo
    dd if=/proc/$PID/mem bs=1 count=$DUMP_SIZE skip=$START_DEC 2>/dev/null | \
    hexdump -C | head -n $((DUMP_SIZE / 16 + 1))
    echo
else
    echo "  [heap] not found"
    echo
fi

echo "--- ALL MAPPINGS ---"
cat /proc/$PID/maps | grep -E '(sigdream|\[heap\]|\[stack\])'
echo
