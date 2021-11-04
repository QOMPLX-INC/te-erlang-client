%%-------------------------------------------------------------------
%% @doc
%%-------------------------------------------------------------------

-module(texample).
-export([start/0]).

-spec start() -> ok.
start() ->
    io:format(">>> loadind dependencies...~n"),
    _ = [ application:start(Dep) || Dep <- resolve_deps(texample),
                                           not is_otp_base_app(Dep) ],
    ok.

-spec dep_apps(atom()) -> [atom()].
dep_apps(App) ->
    application:load(App),
    {ok, Apps} = application:get_key(App, applications),
    Apps.

-spec all_deps(atom(), [atom()]) -> [atom()].
all_deps(App, Deps) ->
    [[ all_deps(Dep, [App|Deps]) || Dep <- dep_apps(App),
                                           not lists:member(Dep, Deps)], App].

-spec resolve_deps(atom()) -> [atom()].
resolve_deps(App) ->
    DepList = all_deps(App, []),
    {AppOrder, _} = lists:foldl(fun(A,{List,Set}) ->
                                        case maps:is_key(A, Set) of
                                            true ->
                                                {List, Set};
                                            false ->
                                                {List ++ [A], Set#{A => 1}}
                                        end
                                end,
                                {[], #{}},
                                lists:flatten(DepList)),
    AppOrder.

-spec is_otp_base_app(atom()) -> boolean().
is_otp_base_app(kernel) -> true;
is_otp_base_app(stdlib) -> true;
is_otp_base_app(_) -> false.

%%-------------------------------------------------------------------
