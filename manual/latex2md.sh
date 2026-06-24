#!/bin/sh

cp -f tracy.tex _tmp.tex
sed -i -e 's@\\menu\[,\]@@g' _tmp.tex
sed -i -e 's@\\keys@@g' _tmp.tex
sed -i -e 's@\\ctrl@Ctrl@g' _tmp.tex
sed -i -e 's@\\shift@Shift@g' _tmp.tex
sed -i -e 's@\\Alt@Alt@g' _tmp.tex
sed -i -e 's@\\del@Delete@g' _tmp.tex
python3 fa-icons.py ../profiler/src/profiler/IconsFontAwesome7.h _tmp.tex
sed -i -e 's@\\LMB{}~@@g' _tmp.tex
sed -i -e 's@\\MMB{}~@@g' _tmp.tex
sed -i -e 's@\\RMB{}~@@g' _tmp.tex
sed -i -e 's@\\Scroll{}~@@g' _tmp.tex
sed -i -e 's@\\textsigma@σ@g' _tmp.tex

# Resolve \circled{} markers and lstlisting escapeinside (@...@) snippets, which
# pandoc would otherwise emit verbatim or drop, to their Unicode equivalents.
sed -i -e 's|@\\circled{a}@|(a)|g' -e 's|@\\circled{b}@|(b)|g' -e 's|@\\circled{c}@|(c)|g' _tmp.tex
sed -i -e 's|\\circled{a}|(a)|g' -e 's|\\circled{b}|(b)|g' -e 's|\\circled{c}|(c)|g' _tmp.tex
sed -i -e 's|@\\ldots@|…|g' _tmp.tex

sed -i -e 's@\\nameref{quicklook}@A quick look at Tracy Profiler@g' _tmp.tex
sed -i -e 's@\\nameref{firststeps}@First steps@g' _tmp.tex
sed -i -e 's@\\nameref{client}@Client markup@g' _tmp.tex
sed -i -e 's@\\nameref{capturing}@Capturing the data@g' _tmp.tex
sed -i -e 's@\\nameref{analyzingdata}@Analyzing captured data@g' _tmp.tex
sed -i -e 's@\\nameref{tracyassist}@Tracy Assist@g' _tmp.tex
sed -i -e 's@\\nameref{csvexport}@Exporting zone statistics to CSV@g' _tmp.tex
sed -i -e 's@\\nameref{importingdata}@Importing external profiling data@g' _tmp.tex
sed -i -e 's@\\nameref{configurationfiles}@Configuration files@g' _tmp.tex

awk -f bclogo2quote.awk _tmp.tex > _tmp_quoted.tex
mv _tmp_quoted.tex _tmp.tex

pandoc --wrap=none --reference-location=block --number-sections -L filter.lua -t 'markdown-simple_tables-multiline_tables-grid_tables+pipe_tables' -s _tmp.tex -o tracy.md

awk -f tablecaption.awk tracy.md > _tmp_caption.md
mv _tmp_caption.md tracy.md

sed -i -e 's/^> \*\*IMPORTANT:\([^*]*\)\*\*/> [!IMPORTANT]\
> **\1**/' tracy.md
sed -i -e 's/^> \*\*TIP:\([^*]*\)\*\*/> [!TIP]\
> **\1**/' tracy.md
sed -i -e 's/^> \*\*CAUTION:\([^*]*\)\*\*/> [!CAUTION]\
> **\1**/' tracy.md
sed -i -e 's/^> \*\*NOTE:\([^*]*\)\*\*/> [!NOTE]\
> **\1**/' tracy.md

python3 icon-explain.py ../profiler/src/profiler/IconsFontAwesome7.h tracy.md

rm -f _tmp.tex
