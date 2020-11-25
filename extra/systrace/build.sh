#!/bin/sh
: ${CC:=clang}
: ${STRIP:=strip}
: ${SSTRIP:=}

$CC tracy_systrace.c -s -Os -ffunction-sections -fdata-sections -Wl,--gc-sections -fno-stack-protector -Wl,-z,norelro -Wl,--build-id=none -nostdlib -ldl -o tracy_systrace

$STRIP --strip-all -R .note.gnu.gold-version -R .comment -R .note -R .note.gnu.build-id -R .note.ABI-tag -R .eh_frame -R .eh_frame_hdr -R .gnu.hash -R .gnu.version -R .got tracy_systrace

if [[ ! -z "$SSTRIP" ]]
then
  $SSTRIP -z tracy_systrace
fi

