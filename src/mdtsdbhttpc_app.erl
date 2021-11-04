%%------------------------------------------------------------------

-module(mdtsdbhttpc_app).
-behaviour(application).

%% API.
-export([start/2]).
-export([stop/1]).

%%------------------------------------------------------------------
%% API functions
%%------------------------------------------------------------------

start(_Type, _Args) ->
    mdtsdbhttpc_sup:start_link().

stop(_State) ->
    ok.

