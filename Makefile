PLTFILE=$(CURDIR)/.deps.plt
APP_DEPS=kernel stdlib crypto ssl tools eunit compiler public_key mnesia erts

REBAR=$(shell which rebar)
ifeq ($(REBAR),)
$(error "Rebar is not presented")
endif

ERL=$(shell which erl)
ifeq ($(ERL),)
$(error "Erlang is not presented")
endif

PLT_INC=$(shell test -d deps && echo '-r deps')
DIALYSER_INC=$(shell include -d deps && echo '-I include') $(shell test -d deps && echo '-I deps')

all: get-deps compile

rebuild: distclean get-deps compile

get-deps: 
	@$(REBAR) -C rebar.config get-deps

compile: 
	@$(REBAR) -C rebar.config skip_deps=true compile

doc:
	@$(REBAR) -C rebar.config skip_deps=true doc

clean: 
	@$(REBAR) -C rebar.config skip_deps=true clean

test: get-deps 
	@$(REBAR) -C rebar.config -DTEST skip_deps=true compile ct

xref: get-deps compile
	@$(REBAR) -C rebar.config skip_deps=true xref

$(PLTFILE): 
	- dialyzer --build_plt --apps $(APP_DEPS) $(PLT_INC) --output_plt $(PLTFILE)

dialyzer: get-deps compile $(PLTFILE)
	dialyzer --fullpath --plt $(PLTFILE) $(DIALYSER_INC) -pa $(CURDIR)/ebin --src src

typer:
	typer --plt $(PLTFILE) $(DIALYSER_INC) -r src

clean-plt:
	@rm -rf $(PLTFILE)

clean-deps:
	@rm -rfv $(CURDIR)/deps/*

distclean: clean clean-plt clean-deps
	
travis: dialyzer
