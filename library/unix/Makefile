all: release

debug:
	@$(MAKE) -f debug.mk all

release:
	@$(MAKE) -f release.mk all

clean:
	@$(MAKE) -f build.mk clean
	rm -f libtracy-*.so

db: clean
	@bear -- $(MAKE) -f debug.mk all
	@mv -f compile_commands.json ../../

.PHONY: all clean debug release db
