all: release

debug:
	@+make -f debug.mk all

release:
	@+make -f release.mk all

clean:
	@+make -f build.mk clean

serve:
	@python httpd.py

.PHONY: all clean debug release serve
