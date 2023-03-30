all: release

debug:
	@+make -f debug.mk all

release:
	@+make -f release.mk all

clean:
	@+make -f build.mk clean
	rm -f libtracy-*.so

db: clean
	@bear -- $(MAKE) -f debug.mk all
	@mv -f compile_commands.json ../../

.PHONY: all clean debug release db
