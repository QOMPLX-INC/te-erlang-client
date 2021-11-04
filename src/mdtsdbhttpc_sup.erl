%%------------------------------------------------------------------

-module(mdtsdbhttpc_sup).
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

%%------------------------------------------------------------------
%% API functions
%%------------------------------------------------------------------

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    Childs = [],
    {ok, {{one_for_one, 10, 10}, Childs}}.


%% ---------------------------------
%% Internal functions
%% ---------------------------------
