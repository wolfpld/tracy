#!/bin/sh

cp -f tracy.tex _tmp.tex
sed -i -e 's@\\menu[,]@@g' _tmp.tex
sed -i -e 's@\\keys@@g' _tmp.tex
sed -i -e 's@\\ctrl@Ctrl@g' _tmp.tex
sed -i -e 's@\\shift@Shift@g' _tmp.tex
sed -i -e 's@\\Alt@Alt@g' _tmp.tex
sed -i -e 's@\\del@Delete@g' _tmp.tex

pandoc --wrap=none --reference-location=block --number-sections -s _tmp.tex -o tracy.md
rm -f _tmp.tex
