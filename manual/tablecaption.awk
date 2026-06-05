# Pandoc emits table captions as a line beginning with ": ", which GitHub
# renders literally instead of as a caption. Strip the marker and italicize
# the caption instead. Captions may span several physical lines when they
# contain a hard line break (a trailing backslash). Underscores are used for
# the emphasis so captions that already contain "*...*" markup are left intact.
!incap && /^: / {
    incap = 1
    $0 = "_" substr($0, 3)
}
incap && !/\\$/ {
    print $0 "_"
    incap = 0
    next
}
incap { print; next }
{ print }
