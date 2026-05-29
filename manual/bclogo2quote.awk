/\\begin\{bclogo\}\[/ {
    in_bclogo = 1
    bclogo_type = ""
    next
}
in_bclogo && /logo=/ {
    if (/\\bcbombe/) bclogo_type = "bcbombe"
    else if (/\\bcattention/) bclogo_type = "bcattention"
    else if (/\\bclampe/) bclogo_type = "bclampe"
    else if (/\\bcquestion/) bclogo_type = "bcquestion"
    next
}
in_bclogo && /noborder|couleur/ {
    next
}
in_bclogo {
    line = $0
    sub(/^[ \t]*\]?\{/, "", line)
    sub(/\}.*$/, "", line)
    bclogo_title = line

    if (bclogo_type == "bcbombe") prefix = "IMPORTANT"
    else if (bclogo_type == "bcattention") prefix = "CAUTION"
    else if (bclogo_type == "bclampe") prefix = "TIP"
    else prefix = "NOTE"

    printf "\\begin{quote}\\textbf{%s:%s}\\par\n", prefix, bclogo_title
    in_bclogo = 0
    next
}
/\\end\{bclogo\}/ {
    printf "\\end{quote}\n"
    next
}
{ print }