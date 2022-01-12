# Extract the actual list of source files from a sibling Visual Studio project.

# Ensure these are simply-substituted variables, without changing their values.
SRC := $(SRC)
SRC2 := $(SRC2)
SRC3 := $(SRC3)
SRC4 := $(SRC4)

# Paths here are relative to the directory in which make was invoked, not to
# this file, so ../win32/$(PROJECT).vcxproj refers to the Visual Studio project
# of whichever tool is including this makefile fragment.

BASE := $(shell egrep 'ClCompile.*cpp"' ../win32/$(PROJECT).vcxproj | sed -e 's/.*\"\(.*\)\".*/\1/' | sed -e 's@\\@/@g')
BASE2 := $(shell egrep 'ClCompile.*c"' ../win32/$(PROJECT).vcxproj | sed -e 's/.*\"\(.*\)\".*/\1/' | sed -e 's@\\@/@g')
BASE4 := $(shell egrep 'None.*S"' ../win32/$(PROJECT).vcxproj | sed -e 's/.*\"\(.*\)\".*/\1/' | sed -e 's@\\@/@g')

# The tool-specific makefile may request that certain files be omitted.
SRC += $(filter-out $(FILTER),$(BASE))
SRC2 += $(filter-out $(FILTER),$(BASE2))
SRC3 += $(filter-out $(FILTER),$(BASE3))
SRC4 += $(filter-out $(FILTER),$(BASE4))
