function Link(el)
  el.attributes['reference-type'] = nil
  el.attributes['reference'] = nil
  return el
end

-- Drop Div wrappers (e.g. table/titlepage containers), keeping their content.
function Div(el)
  return el.content
end
