all: release

embed.tracy:
	wget https://share.nereid.pl/i/embed.tracy

debug: embed.tracy
	@$(MAKE) -f debug.mk all TRACY_NO_ISA_EXTENSIONS=1

release: embed.tracy
	@$(MAKE) -f release.mk all TRACY_NO_ISA_EXTENSIONS=1

clean:
	@$(MAKE) -f build.mk clean
	rm -rf Tracy-release.*
	rm -rf Tracy-debug.*

serve:
	@python httpd.py

.PHONY: all clean debug release serve
