REBAR=$(shell which rebar3)

.PHONY: rel doc

all: compile

compile: checkrebar3
	@$(REBAR) compile

clean:
	@$(REBAR) clean

doc:
	@$(REBAR) edoc

dialyzer:
	@dialyzer -nn -r _build/default/lib/mdtsdbhttpc/ebin/

ct:
	@$(REBAR) ct skip_deps=true

rebuild: checkrebar3
	@$(REBAR) compile
	@dialyzer -nn -r ./ebin/
	@$(REBAR) ct skip_deps=true
	@$(REBAR) edoc skip_deps=true

checkrebar3:
ifeq ($(REBAR),)
	@rm -rf /tmp/rebar3 2> /dev/null
	@git clone https://github.com/rebar/rebar3.git /tmp/rebar3 && \
	cd /tmp/rebar3/ && \
	./bootstrap && \
	mv rebar3 ~/bin
	@rm -rf /tmp/rebar3
	REBAR=~/bin/rebar3 2> /dev/null
endif
