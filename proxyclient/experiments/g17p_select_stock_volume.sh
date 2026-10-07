#!/bin/sh

OUT=/Users/Shared/g17p_select_stock.log
LIST=/tmp/g17p_startup_disks.txt
RESULT=/tmp/g17p_set_startup_disk.txt
BLESS_RESULT=/tmp/g17p_bless_startup_disk.txt

say()
{
    printf '%s\n' "$*" | /usr/bin/tee -a "$OUT" >/dev/console
}

: >"$OUT"
say "G17P_SELECT_STOCK_BEGIN $(/bin/date)"
/bin/sleep 120
/usr/sbin/systemsetup -liststartupdisks >"$LIST" 2>&1
/bin/sleep 30
/usr/sbin/systemsetup -liststartupdisks >"$LIST" 2>&1
/bin/cat "$LIST" | /usr/bin/tee -a "$OUT" >/dev/console
TARGET=$(/usr/bin/grep -i 'custom-macos' "$LIST" | /usr/bin/head -1 |
    /usr/bin/sed 's/^[[:space:]]*//')
if test -z "$TARGET" -a \
    -d '/Volumes/custom-macos/System/Library/CoreServices'; then
    TARGET='/Volumes/custom-macos/System/Library/CoreServices'
fi
if test -z "$TARGET"; then
    TARGET=$(/usr/bin/grep '^/' "$LIST" | /usr/bin/grep -vi debugusb |
        /usr/bin/head -1 | /usr/bin/sed 's/^[[:space:]]*//')
fi
say "G17P_SELECT_STOCK_TARGET=$TARGET"
if test -n "$TARGET"; then
    /usr/sbin/systemsetup -setstartupdisk "$TARGET" >"$RESULT" 2>&1
    STATUS=$?
else
    printf '%s\n' 'No non-debugusb startup disk found' >"$RESULT"
    STATUS=1
fi
/bin/cat "$RESULT" | /usr/bin/tee -a "$OUT" >/dev/console
say "G17P_SELECT_STOCK_STATUS=$STATUS"
/usr/sbin/systemsetup -getstartupdisk 2>&1 |
    /usr/bin/tee -a "$OUT" >/dev/console

# systemsetup only accepts paths returned by -liststartupdisks, but macOS 26
# does not list sibling APFS system volumes in this nested debug guest.  bless
# mount mode is the Apple-silicon interface for selecting an already-blessed
# volume.  Make this a one-boot selection so the debugusb workflow remains the
# persistent default.
if test "$STATUS" -ne 0 -a -d /Volumes/custom-macos; then
    /usr/sbin/bless --info /Volumes/custom-macos --plist 2>&1 |
        /usr/bin/tee -a "$OUT" >/dev/console
    /usr/sbin/bless --mount /Volumes/custom-macos --setBoot --nextonly \
        --verbose >"$BLESS_RESULT" 2>&1
    BLESS_STATUS=$?
    /bin/cat "$BLESS_RESULT" | /usr/bin/tee -a "$OUT" >/dev/console
    say "G17P_SELECT_STOCK_BLESS_STATUS=$BLESS_STATUS"
else
    BLESS_STATUS=$STATUS
fi
/usr/sbin/bless --getBoot 2>&1 | /usr/bin/tee -a "$OUT" >/dev/console
say "G17P_SELECT_STOCK_COMPLETE $(/bin/date)"
