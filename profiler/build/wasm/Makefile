all: release

embed.tracy:
	wget https://share.nereid.pl/i/embed.tracy

debug: embed.tracy
	@+make -f debug.mk all TRACY_NO_ISA_EXTENSIONS=1

release: embed.tracy
	@+make -f release.mk all TRACY_NO_ISA_EXTENSIONS=1

clean:
	@+make -f build.mk clean
	rm -rf Tracy-release.*
	rm -rf Tracy-debug.*

serve:
	@python httpd.py

.PHONY: all clean debug release serve
