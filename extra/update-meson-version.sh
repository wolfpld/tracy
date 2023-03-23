#!/bin/sh

version_header="../public/common/TracyVersion.hpp"

major=$(grep -o -E 'Major = [0-9]+' "$version_header" | awk -F '= ' '{print $2}')
minor=$(grep -o -E 'Minor = [0-9]+' "$version_header" | awk -F '= ' '{print $2}')
patch=$(grep -o -E 'Patch = [0-9]+' "$version_header" | awk -F '= ' '{print $2}')

version="${major}.${minor}.${patch}"

# the extension is required for macOS's outdated sed
sed -i.bak "s/version: '[0-9]*\.[0-9]*\.[0-9]*'/version: '$version'/g" ../meson.build
rm ../meson.build.bak
