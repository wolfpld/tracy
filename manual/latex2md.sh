#!/bin/sh

cp -f tracy.tex _tmp.tex
sed -i -e 's@\\menu\[,\]@@g' _tmp.tex
sed -i -e 's@\\keys@@g' _tmp.tex
sed -i -e 's@\\ctrl@Ctrl@g' _tmp.tex
sed -i -e 's@\\shift@Shift@g' _tmp.tex
sed -i -e 's@\\Alt@Alt@g' _tmp.tex
sed -i -e 's@\\del@Delete@g' _tmp.tex
sed -i -e 's@\\fa\([a-zA-Z]*\)@(\1~icon)@g' _tmp.tex
sed -i -e 's@\\LMB{}~@@g' _tmp.tex
sed -i -e 's@\\MMB{}~@@g' _tmp.tex
sed -i -e 's@\\RMB{}~@@g' _tmp.tex
sed -i -e 's@\\Scroll{}~@@g' _tmp.tex

sed -i -e 's@\\nameref{quicklook}@A quick look at Tracy Profiler@g' _tmp.tex
sed -i -e 's@\\nameref{firststeps}@First steps@g' _tmp.tex
sed -i -e 's@\\nameref{client}@Client markup@g' _tmp.tex
sed -i -e 's@\\nameref{capturing}@Capturing the data@g' _tmp.tex
sed -i -e 's@\\nameref{analyzingdata}@Analyzing captured data@g' _tmp.tex
sed -i -e 's@\\nameref{csvexport}@Exporting zone statistics to CSV@g' _tmp.tex
sed -i -e 's@\\nameref{importingdata}@Importing external profiling data@g' _tmp.tex
sed -i -e 's@\\nameref{configurationfiles}@Configuration files@g' _tmp.tex

pandoc --wrap=none --reference-location=block --number-sections -L filter.lua -s _tmp.tex -o tracy.md
rm -f _tmp.tex
