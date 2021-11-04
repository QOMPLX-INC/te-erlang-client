REBAR=$(shell which rebar3)

.PHONY: all compile deps

all: deps compile

deps:
	@$(REBAR) get-deps

compile: checkrebar3 deps
	@$(REBAR) compile

run: compile
	@$(REBAR) shell

clean:
	@$(REBAR) clean

rebuild: checkrebar3
	@$(REBAR) compile

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
