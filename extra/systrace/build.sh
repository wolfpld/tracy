#!/bin/sh

# These may be passed as environment variables, or will use the following defaults.
: ${CC:=clang}
: ${STRIP:=strip}
: ${SSTRIP:=sstrip}

if [ ! -x "$(command -v "${CC}")" ]
then
  echo "Set the CC environment variable to a C compiler."
  exit 1
fi

if [ ! -x "$(command -v "${STRIP}")" ]
then
  echo "Set the STRIP environment variable to the strip utility."
  exit 1
fi

if [ ! -x "$(command -v "${SSTRIP}")" ]
then
  echo "Set the SSTRIP environment variable to the sstrip utility, which can be obtained from https://github.com/BR903/ELFkickers ."
  exit 1
fi

$CC tracy_systrace.c -s -Os -ffunction-sections -fdata-sections -Wl,--gc-sections -fno-stack-protector -Wl,-z,norelro -Wl,--build-id=none -nostdlib -ldl -o tracy_systrace

$STRIP --strip-all -R .note.gnu.gold-version -R .comment -R .note -R .note.gnu.build-id -R .note.ABI-tag -R .eh_frame -R .eh_frame_hdr -R .gnu.version -R .got tracy_systrace

$SSTRIP -z tracy_systrace

