# Patch RGFW.h to fix the macOS WebGPU surface function (void* → id casts):
#   id* nsView = (id*)...               →  id nsView = (id)...
#   objc_msgSend(..., metalLayer)       →  objc_msgSend(..., (id)metalLayer)
#   layer = metalLayer                  →  layer = (id)metalLayer

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/RGFW.h" _src)

string(REPLACE
    "id* nsView = (id*)window->src.view;"
    "id nsView = (id)window->src.view;"
    _src "${_src}"
)

string(REPLACE
    "sel_registerName(\"setLayer:\"), metalLayer);"
    "sel_registerName(\"setLayer:\"), (id)metalLayer);"
    _src "${_src}"
)

string(REPLACE
    "\tlayer = metalLayer;"
    "\tlayer = (id)metalLayer;"
    _src "${_src}"
)

file(WRITE "${CMAKE_CURRENT_SOURCE_DIR}/RGFW.h" "${_src}")
