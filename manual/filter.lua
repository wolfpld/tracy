function Link(el)
  el.attributes['reference-type'] = nil
  el.attributes['reference'] = nil
  return el
end

-- Drop Div wrappers (e.g. table/titlepage containers), keeping their content.
function Div(el)
  return el.content
end

-- ---------------------------------------------------------------------------
-- LaTeX math -> plain-text approximation.
--
-- The target Markdown renderer has no math support, so a raw "$\frac{1}{2}$"
-- would show verbatim. We turn each math node into the closest Unicode/ASCII
-- equivalent: fractions become "a/b", \times becomes "x", super/subscripts use
-- Unicode digits, and the one multi-line display equation becomes a fenced
-- code block (Markdown collapses plain newlines, a code block keeps them).
-- ---------------------------------------------------------------------------

local sup = {['0']='⁰',['1']='¹',['2']='²',['3']='³',['4']='⁴',['5']='⁵',
             ['6']='⁶',['7']='⁷',['8']='⁸',['9']='⁹',['+']='⁺',['-']='⁻',
             ['=']='⁼',['(']='⁽',[')']='⁾'}
local sub = {['0']='₀',['1']='₁',['2']='₂',['3']='₃',['4']='₄',['5']='₅',
             ['6']='₆',['7']='₇',['8']='₈',['9']='₉',['+']='₊',['-']='₋',
             ['=']='₌',['(']='₍',[')']='₎'}

-- Symbol replacements, applied as literal substitutions. Longer commands must
-- precede those that are a prefix of them (e.g. \rightarrow before \right).
local symbols = {
  {'\\leftrightarrow','↔'}, {'\\rightarrow','→'}, {'\\leftarrow','←'},
  {'\\Rightarrow','⇒'}, {'\\Leftarrow','⇐'}, {'\\to','→'}, {'\\mapsto','↦'},
  {'\\times','×'}, {'\\cdot','·'}, {'\\div','÷'}, {'\\ast','*'}, {'\\star','*'},
  {'\\leq','≤'}, {'\\geq','≥'}, {'\\neq','≠'}, {'\\approx','≈'}, {'\\equiv','≡'},
  {'\\ll','«'}, {'\\gg','»'}, {'\\le','≤'}, {'\\ge','≥'},
  {'\\ldots','…'}, {'\\cdots','…'}, {'\\dots','…'}, {'\\infty','∞'},
  {'\\pm','±'}, {'\\mp','∓'}, {'\\propto','∝'}, {'\\sum','Σ'}, {'\\prod','Π'},
  {'\\alpha','α'}, {'\\beta','β'}, {'\\gamma','γ'}, {'\\delta','δ'}, {'\\Delta','Δ'},
  {'\\mu','µ'}, {'\\sigma','σ'}, {'\\pi','π'}, {'\\lambda','λ'}, {'\\theta','θ'},
  {'\\left',''}, {'\\right',''},
  {'\\qquad','    '}, {'\\quad','  '}, {'\\,',' '}, {'\\;',' '}, {'\\:',' '},
  {'\\ ',' '}, {'\\!',''},
  {'\\%','%'}, {'\\#','#'}, {'\\&','&'}, {'\\_','_'}, {'\\{','{'}, {'\\}','}'},
  {'\\$','$'},
}

-- Literal (non-pattern) string replacement; avoids Lua pattern magic in keys.
local function lit_replace(s, a, b)
  local out, i = {}, 1
  while true do
    local p = s:find(a, i, true)
    if not p then out[#out + 1] = s:sub(i); break end
    out[#out + 1] = s:sub(i, p - 1)
    out[#out + 1] = b
    i = p + #a
  end
  return table.concat(out)
end

-- Strip the outer braces of a "%b{}" capture.
local function grp(b) return b:sub(2, #b - 1) end

-- Map a string to Unicode super/subscript, or nil if any char is unsupported.
local function map_script(txt, map)
  local res = {}
  for i = 1, #txt do
    local c = txt:sub(i, i)
    if not map[c] then return nil end
    res[#res + 1] = map[c]
  end
  return table.concat(res)
end

local function convert(s)
  -- Text/font wrappers: keep the content, recurse to handle nesting.
  for _, cmd in ipairs({'text', 'mathrm', 'mathit', 'mathbf', 'mathbb',
                        'mathsf', 'mathtt', 'mathcal', 'operatorname',
                        'textbf', 'textit', 'textrm'}) do
    s = s:gsub('\\' .. cmd .. '(%b{})', function(b) return convert(grp(b)) end)
  end
  -- Fractions -> "num/den" (spaced when either side has spaces).
  local function frac(a, b)
    local n, d = convert(grp(a)), convert(grp(b))
    local sep = (n:find(' ', 1, true) or d:find(' ', 1, true)) and ' / ' or '/'
    return n .. sep .. d
  end
  s = s:gsub('\\frac(%b{})(%b{})', frac)
  s = s:gsub('\\dfrac(%b{})(%b{})', frac)
  s = s:gsub('\\tfrac(%b{})(%b{})', frac)
  s = s:gsub('\\sfrac(%b{})(%b{})', frac)
  -- Roots.
  s = s:gsub('\\sqrt(%b{})', function(b) return '√(' .. convert(grp(b)) .. ')' end)
  -- Single-char scripts first, so the braced fallback (e.g. "_native") below
  -- is not re-scanned and mangled into Unicode subscripts.
  s = s:gsub('%^([%w])', function(c) return sup[c] or ('^' .. c) end)
  s = s:gsub('_([%w])', function(c) return sub[c] or ('_' .. c) end)
  -- Braced scripts: Unicode when the content is all digits/signs, else keep
  -- a readable "^(...)" / "_..." form.
  s = s:gsub('%^(%b{})', function(b)
    local inner = convert(grp(b))
    return map_script(inner, sup) or ('^(' .. inner .. ')')
  end)
  s = s:gsub('_(%b{})', function(b)
    local inner = convert(grp(b))
    return map_script(inner, sub) or ('_' .. inner)
  end)
  -- Remaining symbols.
  for _, pair in ipairs(symbols) do s = lit_replace(s, pair[1], pair[2]) end
  return s
end

-- Convert a display equation, preserving its line structure for a code block.
local function convert_display(s)
  s = convert(s)
  for _, env in ipairs({'cases', 'aligned', 'align', 'array', 'matrix',
                        'gathered', 'split'}) do
    s = lit_replace(s, '\\begin{' .. env .. '}', '')
    s = lit_replace(s, '\\end{' .. env .. '}', '')
  end
  s = lit_replace(s, '\\\\', '\n')   -- row break
  s = s:gsub('%s*&%s*', '   ')        -- column separator -> spacing
  local lines = {}
  for line in (s .. '\n'):gmatch('(.-)\n') do
    line = line:gsub('^%s+', ''):gsub('%s+$', '')
    if line ~= '' then lines[#lines + 1] = line end
  end
  for i = 2, #lines do lines[i] = '    ' .. lines[i] end  -- indent continuations
  return table.concat(lines, '\n')
end

function Math(el)
  if el.mathtype == 'DisplayMath' then
    return el  -- handled at block level by Para, to emit a code block
  end
  return pandoc.Str(convert(el.text))
end

-- A paragraph that is solely a display equation becomes a fenced code block.
function Para(el)
  local maths, only_math = {}, true
  for _, x in ipairs(el.content) do
    if x.t == 'Math' and x.mathtype == 'DisplayMath' then
      maths[#maths + 1] = x
    elseif x.t ~= 'Space' and x.t ~= 'SoftBreak' and x.t ~= 'LineBreak' then
      only_math = false
    end
  end
  if #maths == 0 or not only_math then return nil end
  local parts = {}
  for _, m in ipairs(maths) do parts[#parts + 1] = convert_display(m.text) end
  return pandoc.CodeBlock(table.concat(parts, '\n\n'))
end
