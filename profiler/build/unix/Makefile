ifneq ($(shell uname),Linux)
    export LEGACY=1
endif

all: release

debug:
	@$(MAKE) -f debug.mk all

release:
	@$(MAKE) -f release.mk all

clean:
	@$(MAKE) -f build.mk clean

db: clean
	@bear -- $(MAKE) -f debug.mk all
	@mv -f compile_commands.json ../../../

.PHONY: all clean debug release db
