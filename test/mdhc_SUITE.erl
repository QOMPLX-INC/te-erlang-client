%%-------------------------------------------------------------------4
%%
%% TimeEngine Erlang HTTP Client
%%
%% Copyright 2015-2021 -- QOMPLX, Inc. -- All Rights Reserved.  No License Granted.
%%
%%-------------------------------------------------------------------

-module(mdhc_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").
-include_lib("../include/mdhc.hrl").

-define(HTTPC_POOL_SIZE, 100).
-define(DEF_TEST_HOST, "time-engine.qee.qomplxos.com").
-define(DEF_TEST_PORT, 443).
-define(DEF_TEST_ISHTTPS, true).

-define(DEF_USER_KEY, <<"MyUser">>).
-define(DEF_USER_SECRET, <<"MySecret">>).

-define(N_KEYS, 10000.0).

%%--------------------------------------------------------------------
%% COMMON TEST CALLBACK FUNCTIONS
%%--------------------------------------------------------------------

%%--------------------------------------------------------------------
%% @doc
%%  Returns list of tuples to set default properties
%%  for the suite.
%%
%% Function: suite() -> Info
%%
%% Info = [tuple()]
%%   List of key/value pairs.
%%
%% Note: The suite/0 function is only meant to be used to return
%% default data values, not perform any other operations.
%%
%% @spec suite() -> Info
%% @end
%%--------------------------------------------------------------------
suite() ->
    [{timetrap,{minutes,2880}}].

%%--------------------------------------------------------------------
%% @doc
%% Initialization before the whole suite
%%
%% Config0 = Config1 = [tuple()]
%%   A list of key/value pairs, holding the test case configuration.
%% Reason = term()
%%   The reason for skipping the suite.
%%
%% Note: This function is free to add any key/value pairs to the Config
%% variable, but should NOT alter/remove any existing entries.
%%
%% @spec init_per_suite(Config0) ->
%%               Config1 | {skip,Reason} | {skip_and_save,Reason,Config1}
%% @end
%%--------------------------------------------------------------------
init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(ssl),
    {ok, _} = application:ensure_all_started(gun),
    {ok, _} = application:ensure_all_started(hackney),
    ok = hackney_pool:start_pool(?MODULE, [{timeout, 120000}, {max_connections, ?HTTPC_POOL_SIZE}]),
    {MasterKey, MasterSecret} =
        {?DEF_USER_KEY,
         ?DEF_USER_SECRET},
    ClientOpts = [
        %trace,
        %profile,
        {httpc, hackney},
        %{httpc, gun},
        {pool, ?MODULE},
        {admin_key, MasterKey},
        {secret_key, MasterSecret},
        {use_https, ?DEF_TEST_ISHTTPS}
    ],
    AuthOpts = [
        %{mdtsdb_access_token, <<"...">>}
        %{mdtsdb_auth_url, <<"...">>},
        %{mdtsdb_auth_client_id, <<"...">>},
        %{mdtsdb_auth_client_secret, <<"...">>}
    ],
    [
        {mdtsdb_client_opts, ClientOpts},
        {mdtsdb_auth_opts, AuthOpts} | Config
    ].

%%--------------------------------------------------------------------
%% @doc
%% Cleanup after the whole suite
%%
%% Config - [tuple()]
%%   A list of key/value pairs, holding the test case configuration.
%%
%% @spec end_per_suite(Config) -> _
%% @end
%%--------------------------------------------------------------------
end_per_suite(_Config) ->
    hackney_pool:stop_pool(?MODULE),
    ok.

%%--------------------------------------------------------------------
%% @doc
%% Initialization before each test case group.
%%
%% GroupName = atom()
%%   Name of the test case group that is about to run.
%% Config0 = Config1 = [tuple()]
%%   A list of key/value pairs, holding configuration data for the group.
%% Reason = term()
%%   The reason for skipping all test cases and subgroups in the group.
%%
%% @spec init_per_group(GroupName, Config0) ->
%%               Config1 | {skip,Reason} | {skip_and_save,Reason,Config1}
%% @end
%%--------------------------------------------------------------------
init_per_group(_GroupName, Config) ->
    Config.

%%--------------------------------------------------------------------
%% @doc
%% Cleanup after each test case group.
%%
%% GroupName = atom()
%%   Name of the test case group that is finished.
%% Config0 = Config1 = [tuple()]
%%   A list of key/value pairs, holding configuration data for the group.
%%
%% @spec end_per_group(GroupName, Config0) ->
%%               void() | {save_config,Config1}
%% @end
%%--------------------------------------------------------------------
end_per_group(_GroupName, _Config) ->
    ok.

%%--------------------------------------------------------------------
%% @doc
%% Initialization before each test case
%%
%% TestCase - atom()
%%   Name of the test case that is about to be run.
%% Config0 = Config1 = [tuple()]
%%   A list of key/value pairs, holding the test case configuration.
%% Reason = term()
%%   The reason for skipping the test case.
%%
%% Note: This function is free to add any key/value pairs to the Config
%% variable, but should NOT alter/remove any existing entries.
%%
%% @spec init_per_testcase(TestCase, Config0) ->
%%               Config1 | {skip,Reason} | {skip_and_save,Reason,Config1}
%% @end
%%--------------------------------------------------------------------
init_per_testcase(_TestCase, Config) ->
    Config.

%%--------------------------------------------------------------------
%% @doc
%% Cleanup after each test case
%%
%% TestCase - atom()
%%   Name of the test case that is finished.
%% Config0 = Config1 = [tuple()]
%%   A list of key/value pairs, holding the test case configuration.
%%
%% @spec end_per_testcase(TestCase, Config0) ->
%%               void() | {save_config,Config1} | {fail,Reason}
%% @end
%%--------------------------------------------------------------------
end_per_testcase(_TestCase, _Config) ->
    ok.

%%--------------------------------------------------------------------
%% @doc
%% Returns a list of test case group definitions.
%%
%% Group = {GroupName,Properties,GroupsAndTestCases}
%% GroupName = atom()
%%   The name of the group.
%% Properties = [parallel | sequence | Shuffle | {RepeatType,N}]
%%   Group properties that may be combined.
%% GroupsAndTestCases = [Group | {group,GroupName} | TestCase]
%% TestCase = atom()
%%   The name of a test case.
%% Shuffle = shuffle | {shuffle,Seed}
%%   To get cases executed in random order.
%% Seed = {integer(),integer(),integer()}
%% RepeatType = repeat | repeat_until_all_ok | repeat_until_all_fail |
%%              repeat_until_any_ok | repeat_until_any_fail
%%   To get execution of cases repeated.
%% N = integer() | forever
%%
%% @spec: groups() -> [Group]
%% @end
%%--------------------------------------------------------------------
groups() ->
    [].

%%--------------------------------------------------------------------
%% @doc
%%  Returns the list of groups and test cases that
%%  are to be executed.
%%
%% GroupsAndTestCases = [{group,GroupName} | TestCase]
%% GroupName = atom()
%%   Name of a test case group.
%% TestCase = atom()
%%   Name of a test case.
%% Reason = term()
%%   The reason for skipping all groups and test cases.
%%
%% @spec all() -> GroupsAndTestCases | {skip,Reason}
%% @end
%%--------------------------------------------------------------------
all() ->
    [
     tst_mdhc_1,
     tst_mdhc_2,
     tst_mdhc_3,
     tst_mdhc_4,
     tst_mdhc_5,
     tst_mdhc_6,
     tst_mdhc_7
    ].

%%--------------------------------------------------------------------
%% TEST CASES
%%--------------------------------------------------------------------

%%--------------------------------------------------------------------
%% @doc Test case function. (The name of it must be specified in
%%              the all/0 list or in a test case group for the test case
%%              to be executed).
%%
%% Config0 = Config1 = [tuple()]
%%   A list of key/value pairs, holding the test case configuration.
%% Reason = term()
%%   The reason for skipping the test case.
%% Comment = term()
%%   A comment about the test case that will be printed in the html log.
%%
%% @spec TestCase(Config0) ->
%%           ok | exit() | {skip,Reason} | {comment,Comment} |
%%           {save_config,Config1} | {skip_and_save,Reason,Config1}
%% @end
%%--------------------------------------------------------------------

tst_mdhc_1(Config) ->
    SZ = 3,
    tst_mdhc_1(Config, fun (Ti) ->
        R = lists:map(fun (SensorId) ->
            Value = [
                {v1, [(SensorId + 1) * (Ti + 1) rem X || X <- lists:seq(1, 5)]},
                {v2, SensorId},
                {v3, integer_to_binary(Ti)}
            ],
            {SensorId, [{value, Value}]}
        end, lists:seq(0, SZ)),
        {Ti, R}
    end),
    tst_mdhc_1(Config, fun (Ti) ->
        R = lists:map(fun (SensorId) ->
            Value = [
                {v1, SensorId * Ti rem 3},
                {v2, SensorId},
                {v3, integer_to_binary(Ti)}
            ],
            {SensorId, [{value, Value}]}
        end, lists:seq(0, SZ)),
        {Ti, R}
    end).

tst_mdhc_1(Config, F) ->
    {Verbose, Client1, Client2Adm, Cli} = test_create_clients(Config),
    mdhc:log("    set index fields...", [], Verbose),
    SqlR1 = mdhc:query(Cli, "set index $0.v1: first, $1.v3: last, $2.v2: max, $2.v2: min end."),
    mdhc:log("~p", [SqlR1], Verbose),
    mdhc:log("    prepare data to send...", [], Verbose),
    T0 = mdhc:tnow_lite() - 6000,
    T2 = T0 + 11,
    TimeDataSet = lists:map(F, lists:seq(T0, T2)),
    #{<<"status">> := 1} = mdhc:insert(Cli, TimeDataSet),
    mdhc:log("    query using exact time range", [], Verbose),
    Sql2 = "select first($0.v1), last($1.v3), max($2.v2), min($2.v2) from ~p to ~p format json end.",
    SqlR2 = mdhc:query(Cli, lists:flatten(io_lib:format(Sql2, [T0, T2]))),
    mdhc:log("~p", [SqlR2], Verbose),
    mdhc:log("    query without exact time range", [], Verbose),
    Sql3 = "select first($0.v1), last($1.v3), max($2.v2), min($2.v2) format json end.",
    SqlR3 = mdhc:query(Cli, Sql3),
    mdhc:log("~p", [SqlR3], Verbose),
    mdhc:log("    delete a swimlane...", [], Verbose),
    #{<<"status">> := 1} = mdhc:delete_appkey(Client2Adm, Cli#mdhc.app_key),
    mdhc:log("    delete a user...", [], Verbose),
    #{<<"status">> := 1} = mdhc:delete_adminkey(Client1, Client2Adm#mdhc.admin_key),
    ok.

tst_mdhc_2(Config) ->
    {Verbose, ErrClient1, ErrClient2Adm, ErrCli} = test_create_clients_raw_response(Config),
    mdhc:log("    check error response...", [], Verbose),
    {ok, #{<<"result">> := #{<<"status">> := 1}}} = mdhc:delete_appkey(ErrClient2Adm, ErrCli#mdhc.app_key),
    {ok, #{<<"result">> := #{<<"status">> := 1}}} = mdhc:delete_adminkey(ErrClient1, ErrClient2Adm#mdhc.admin_key),
    %
    {Verbose, Client1, Client2Adm, Cli} = test_create_clients(Config),
    mdhc:log("    set index fields...", [], Verbose),
    SqlR2 = mdhc:query(Cli, "set index $0 end."),
    mdhc:log("~p", [SqlR2], Verbose),
    mdhc:log("    prepare data to send...", [], Verbose),
    T0 = mdhc:tnow_lite() - 6000,
    T2 = T0 + 3,
    F = fun (Ti) ->
        R = lists:map(fun (SensorId) ->
            Value = [
                {v1, SensorId * Ti rem 3},
                {v2, SensorId},
                {v3, integer_to_binary(Ti)}
            ],
            {SensorId, [{value, Value}]}
        end, lists:seq(0, 3)),
        {Ti, R}
    end,
    TimeDataSet = lists:map(F, lists:seq(T0, T2)),
    #{<<"status">> := 1} = mdhc:insert(Cli, TimeDataSet),
    mdhc:log("    got error/warning messages:", [], Verbose),
    Msgs2 = mdhc:get_messages(Cli),
    mdhc:log("~p", [Msgs2], Verbose),
    mdhc:log("    delete a swimlane...", [], Verbose),
    #{<<"status">> := 1} = mdhc:delete_appkey(Client2Adm, Cli#mdhc.app_key),
    mdhc:log("    delete a user...", [], Verbose),
    #{<<"status">> := 1} = mdhc:delete_adminkey(Client1, Client2Adm#mdhc.admin_key),
    ok.



tst_mdhc_3(Config) ->
    {_, Client1, Client2Adm, Cli} = test_create_clients(Config, []),
    mdhc:query(Cli, "env labels: #{2: \"Market\"}, geo_position: #{2: #{\"lat\": -34.919606, \"lng\": -60.152739}} end."),
    NsNow = erlang:system_time(nanosecond),
    Value = #{<<"Price">> => 1.0744497465746132},
    D = [[{ns, NsNow}, {2, [{value, maps:to_list(Value)}]}]],
    #{<<"status">> := 1} = mdhc:insert(Cli, D),
    R = mdhc:query(Cli, "select $2 end."),
    NsNowBin = integer_to_binary(NsNow),
    [[{#{NsNowBin := Value}, <<"c">>, 1}]] = parse_sql_response(R, event, [<<"2">>]),
    #{<<"status">> := 1} = mdhc:delete_appkey(Client2Adm, Cli#mdhc.app_key),
    #{<<"status">> := 1} = mdhc:delete_adminkey(Client1, Client2Adm#mdhc.admin_key),
    ok.

tst_mdhc_4(Config) ->
    Timeout = 15000,
    tst_mdhc_4_1(Config, lists:seq(1, 5) ++ lists:seq(10, 6, -1), undefined, Timeout),
    tst_mdhc_4_1(Config, lists:seq(1, 5) ++ lists:seq(10, 6, -1), true, Timeout),
    tst_mdhc_4_3(Config, [1, 2, 3, #{a => #{b => 1}}, 3, 2, 1], true, Timeout),
    tst_mdhc_4_3(Config, [1, 2, 3, #{a => #{b => 1}}, 3, 2, 1], undefined, Timeout),
    ok.

tst_mdhc_4_1(Config, L, Async, Timeout) ->
    {_, SuperUser, Client2Adm, Client} = test_create_clients(Config),
    try
        {ok, ClientWs} = mdhc:ws_adm_open(Client2Adm#mdhc{app_key = Client#mdhc.app_key}, Async, Timeout),
        Time = tst_mdhc_4_send_flush(ClientWs, L, mdhc:tnow_lite() - 120000, Async, Timeout),
        Alias = <<"0">>,
        Sql = fql("select $~s from ~p to ~p end.", [Alias | Time]),
        tst_mdhc_4_readok(ClientWs, Sql, Alias, L, Async, Timeout),
        ok = mdhc:ws_close(ClientWs)
    after
        #{<<"status">> := 1} = mdhc:delete_appkey(Client2Adm, Client#mdhc.app_key),
        #{<<"status">> := 1} = mdhc:delete_adminkey(SuperUser, Client2Adm#mdhc.admin_key)
    end,
    ok.

tst_mdhc_4_2(Config, L, Async, Timeout) ->
    {_, SuperUser, Client2Adm, Client} = test_create_clients(Config),
    try
        {ok, ClientWs} = mdhc:ws_adm_open(Client2Adm#mdhc{app_key = Client#mdhc.app_key}, Async, Timeout),
        Pattern = <<"\\d\\d\\d\\d-\\d\\d-\\d\\d [\\d:\\.]+ collision: sensor 0 at \\d+">>,
        Sql = "trigger \"alias1\""
              "  insert $0"
              "  do websocket \"{!now} collision: sensor {$sensor} at {$timestamp}\""
              "end.",
        tst_mdhc_4_q(ClientWs, Sql, Async, Timeout),
        Len1 = length(L),
        tst_mdhc_4_esend(ClientWs, L, mdhc:tnow_lite() - 2, Async, Timeout),
        Len1 = tst_mdhc_4_wsall(ClientWs, Timeout, fun ({ok, undefined, FiredMsg}) ->
            {match,[{0, _}]} = re:run(FiredMsg, Pattern)
        end, true, 0),
        L2 = L ++ L,
        Len2 = length(L2),
        tst_mdhc_4_esend(ClientWs, L2, mdhc:tnow_lite(), Async, Timeout),
        Len2 = tst_mdhc_4_wsall(ClientWs, Timeout, fun ({ok, undefined, FiredMsg}) ->
            {match,[{0, _}]} = re:run(FiredMsg, Pattern)
        end, true, 0),
        ok = mdhc:ws_close(ClientWs)
    after
        #{<<"status">> := 1} = mdhc:delete_appkey(Client2Adm, Client#mdhc.app_key),
        #{<<"status">> := 1} = mdhc:delete_adminkey(SuperUser, Client2Adm#mdhc.admin_key)
    end,
    ok.

tst_mdhc_4_3(Config, L, Async, Timeout) ->
    {_, SuperUser, Client2Adm, Client} = test_create_clients(Config),
    try
        {ok, ClientWs} = mdhc:ws_adm_open(Client2Adm#mdhc{app_key = Client#mdhc.app_key}, Async, Timeout),
        T0 = mdhc:tnow_lite() - 120000,
        D = l2senddata(T0, 0, [L], []),
        ErrMsg = <<"wrong data format: nested Json objects are not supported">>,
        ok = mdhc:insert(ClientWs, D),
        if
            Async ->
                {ok, Id2, #{<<"status">> := 1}} = mdhc:ws_parse(ClientWs, mdhc:ws_receive(ClientWs, Timeout)),
                {error, Id2, ErrMsg} = mdhc:ws_parse(ClientWs, mdhc:ws_receive(ClientWs, Timeout));
            true ->
                {error, _, ErrMsg} = mdhc:ws_parse(ClientWs, mdhc:ws_receive(ClientWs, Timeout))
        end,
        ok = mdhc:ws_close(ClientWs)
    after
        #{<<"status">> := 1} = mdhc:delete_appkey(Client2Adm, Client#mdhc.app_key),
        #{<<"status">> := 1} = mdhc:delete_adminkey(SuperUser, Client2Adm#mdhc.admin_key)
    end,
    ok.

tst_mdhc_4_q(ClientWs, Sql, true, Timeout) ->
    ok = mdhc:query(ClientWs, Sql),
    {ok, Id2, #{<<"status">> := 1}} = mdhc:ws_parse(ClientWs, mdhc:ws_receive(ClientWs, Timeout)),
    {ok, Id2, #{<<"status">> := 1}} = mdhc:ws_parse(ClientWs, mdhc:ws_receive(ClientWs, Timeout)),
    ok;

tst_mdhc_4_q(ClientWs, Sql, _, Timeout) ->
    ok = mdhc:query(ClientWs, Sql),
    {ok, _Id2, #{<<"status">> := 1}} = mdhc:ws_parse(ClientWs, mdhc:ws_receive(ClientWs, Timeout)),
    ok.

tst_mdhc_4_wsall(ClientWs, Timeout, F, Verbose, N) ->
    case mdhc:ws_parse(ClientWs, mdhc:ws_receive(ClientWs, Timeout)) of
        {error, undefined, timeout} ->
            N;
        R when Verbose ->
            error_logger:info_msg("~p:~p ~p", [?MODULE, ?LINE, R]),
            F(R),
            tst_mdhc_4_wsall(ClientWs, Timeout, F, Verbose, N + 1);
        R ->
            F(R),
            tst_mdhc_4_wsall(ClientWs, Timeout, F, Verbose, N + 1)
    end.

tst_mdhc_4_readok(ClientWs, Sql, Alias, L, true, Timeout) ->
    ok = mdhc:query(ClientWs, Sql),
    {ok, Id2, #{<<"status">> := 1}} = mdhc:ws_parse(ClientWs, mdhc:ws_receive(ClientWs, Timeout)),
    {ok, Id2, Eq} = mdhc:ws_parse(ClientWs, mdhc:ws_receive(ClientWs, Timeout)),
    L = result2data(Eq, event, Alias),
    ok;

tst_mdhc_4_readok(ClientWs, Sql, Alias, L, _, Timeout) ->
    ok = mdhc:query(ClientWs, Sql),
    {ok, _Id2, Eq} = mdhc:ws_parse(ClientWs, mdhc:ws_receive(ClientWs, Timeout)),
    L = result2data(Eq, event, Alias),
    ok.

tst_mdhc_4_send_flush(ClientWs, L, T0, Async, Timeout) ->
    T2 = T0 + length(L) - 1,
    D = l2senddata(T0, 0, [L], []),
    ok = mdhc:insert(ClientWs, D),
    {ok, Id2, #{<<"status">> := 1}} = mdhc:ws_parse(ClientWs, mdhc:ws_receive(ClientWs, Timeout)),
    if
        Async ->
            {ok, Id2, #{<<"status">> := 1}} = mdhc:ws_parse(ClientWs, mdhc:ws_receive(ClientWs, Timeout));
        true ->
            ok
    end,
    [T0, T2].

tst_mdhc_4_esend(ClientWs, L, T0, Async, Timeout) ->
    T2 = T0 + length(L) - 1,
    D = l2senddata(T0, 0, [L], []),
    ok = mdhc:insert(ClientWs, D),
    {ok, Id2, #{<<"status">> := 1}} = mdhc:ws_parse(ClientWs, mdhc:ws_receive(ClientWs, Timeout)),
    if
        Async ->
            {ok, Id2, #{<<"status">> := 1}} = mdhc:ws_parse(ClientWs, mdhc:ws_receive(ClientWs, Timeout));
        true ->
            ok
    end,
    [T0, T2].

tst_mdhc_5(Config) ->
    Opts = [<<"buffer_off">>, <<"autoclean_off">>],
    NSwimlanes = 20,
    NPoints = 111,
    T0 = mdhc:tnow_lite() - 6000,
    DataF = fun (No) ->
        NoBin = integer_to_binary(No),
        lists:map(fun (T) ->
            [{<<"ns">>, T},
             {0, [
                {value, [
                    {metric, (T - T0) rem 2},
                    {p1, (T - T0) * No},
                    {p2, <<"User", NoBin/binary, $-, (integer_to_binary(T - T0))/binary>>}]}]},
             {1, [
                {value, [
                    {metric, 1 - ((T - T0) rem 2)},
                    {p1, (T - T0 + 1) * No},
                    {p2, <<"User", NoBin/binary, $-, (integer_to_binary(T - T0))/binary>>}]}]}
            ]
        end, lists:seq(T0, T0 + NPoints))
    end,
    Q = lists:flatten(io_lib:format("select $0, $1 from ~p to ~p end.", [T0, T0 + NPoints])),
    SkipL = [<<"ms">>, <<"mb">>, <<"_qsz">>],
    R1 = without(SkipL, tst_mdhc_5_one(Config, Opts, NSwimlanes, DataF, Q)),
    R1 = without(SkipL, tst_mdhc_5_multi(Config, Opts, NSwimlanes, DataF, Q, true)),
    R1 = without(SkipL, tst_mdhc_5_multi(Config, Opts, NSwimlanes, DataF, Q, false)),
    _ = tst_mdhc_5_auto(Config, Opts, NSwimlanes, DataF, Q),
    ok.

tst_mdhc_5_create_clients(Config, Opts, NSwimlanes) ->
    ClientOpts = proplists:get_value(mdtsdb_client_opts, Config),
    Verbose = mdhc:is_trace(#mdhc{options = ClientOpts}),
    SuperClient = mdhc:create(?DEF_TEST_HOST, ?DEF_TEST_PORT, ClientOpts),
    #{<<"key">> := AdmKey1, <<"secret_key">> := SecretAdmKey1} = mdhc:new_adminkey(SuperClient, <<"Adm User">>),
    AdmClient = SuperClient#mdhc{admin_key = AdmKey1, secret_key = SecretAdmKey1},
    Swimlanes = lists:map(fun (No) ->
        #{<<"key">> := AK, <<"secret_key">> := SK} =
                    mdhc:new_appkey(AdmClient, <<"User ", (integer_to_binary(No))/binary>>, Opts),
        AdmClient#mdhc{app_key = AK, secret_key = SK}
    end, lists:seq(1, NSwimlanes)),
    {Verbose, SuperClient, AdmClient, Swimlanes}.

tst_mdhc_5_one(Config, Opts, NSwimlanes, DataF, Q) ->
    {_Verbose, SuperClient, AdmClient, Swimlanes} = tst_mdhc_5_create_clients(Config, Opts, NSwimlanes),
    try
        lists:foldl(fun (Cli, No) ->
            #{<<"status">> := 1} = mdhc:insert(Cli, DataF(No)),
            No + 1
        end, 1, Swimlanes),
        [mdhc:query(Cli, Q) || Cli <- Swimlanes]
    after
        [#{<<"status">> := 1} = mdhc:delete_appkey(AdmClient, Cli#mdhc.app_key) || Cli <- Swimlanes],
        #{<<"status">> := 1} = mdhc:delete_adminkey(SuperClient, AdmClient#mdhc.admin_key)
    end.

tst_mdhc_5_multi(Config, Opts, NSwimlanes, DataF, Q, IsAdmin) ->
    {_Verbose, SuperClient, AdmClient, Swimlanes} = tst_mdhc_5_create_clients(Config, Opts, NSwimlanes),
    try
        {Data, _} = lists:foldl(fun (Cli, {Acc, No}) ->
            {[[
                {<<"key">>, Cli#mdhc.app_key},
                {<<"data">>, DataF(No)}
            ] | Acc], No + 1}
        end, {[], 1}, Swimlanes),
        case IsAdmin of
            true ->
                mdhc:insert(AdmClient, Data);
            false ->
                mdhc:insert(hd(Swimlanes), Data)
        end,
        [mdhc:query(Cli, Q) || Cli <- Swimlanes]
    after
        [#{<<"status">> := 1} = mdhc:delete_appkey(AdmClient, Cli#mdhc.app_key) || Cli <- Swimlanes],
        #{<<"status">> := 1} = mdhc:delete_adminkey(SuperClient, AdmClient#mdhc.admin_key)
    end.

tst_mdhc_5_auto(Config, _Opts, NSwimlanes, DataF, Q) ->
    ClientOpts = proplists:get_value(mdtsdb_client_opts, Config),
    SuperClient = mdhc:create(?DEF_TEST_HOST, ?DEF_TEST_PORT, ClientOpts),
    #{<<"key">> := AdmKey1, <<"secret_key">> := SecretAdmKey1} = mdhc:new_adminkey(SuperClient, <<"Adm User">>),
    AdmClient = SuperClient#mdhc{admin_key = AdmKey1, secret_key = SecretAdmKey1},
    Tags = lists:map(fun (No) ->
        [{<<"index">>, No}]
    end, lists:seq(1, NSwimlanes)),
    try
        {Data, _} = lists:foldl(fun (TagsElem, {Acc, No}) ->
            {[[
                {<<"tags">>, TagsElem},
                {<<"data">>, DataF(No)}
            ] | Acc], No + 1}
        end, {[], 1}, Tags),
        mdhc:insert(AdmClient, Data),
        SwKeys = mdhc:query(AdmClient, "get_swimlanes()."),
        Swimlanes = lists:map(fun (SwKey) ->
            Secret = mdhc:query(AdmClient, lists:flatten(io_lib:format("get_swimlane_secret(\"~s\").", [SwKey]))),
            AdmClient#mdhc{app_key = SwKey, secret_key = Secret}
        end, SwKeys),
        R = [mdhc:query(Cli, Q) || Cli <- Swimlanes],
        [#{<<"status">> := 1} = mdhc:delete_appkey(AdmClient, Cli#mdhc.app_key) || Cli <- Swimlanes],
        R
    after
        #{<<"status">> := 1} = mdhc:delete_adminkey(SuperClient, AdmClient#mdhc.admin_key)
    end.

%%--------------------------------------------------------------------

tst_mdhc_6(Config0) ->
    ClientOpts0 = proplists:get_value(mdtsdb_client_opts, Config0),
    ClientOpts = proplists:delete(trace, ClientOpts0),
    Config = [{mdtsdb_client_opts, ClientOpts} | proplists:delete(mdtsdb_client_opts, Config0)],
    Opts = [<<"buffer_off">>, <<"autoclean_off">>],
    T0 = mdhc:tnow_lite() - 6000000,
    DataF = fun (Key, Ts, NPoints) ->
        lists:map(fun (T) ->
            [{<<"ns">>, T},
             {0, [{value, [{p1, T - T0}, {p2, Key}]}]},
             {1, [{value, [{p1, T}, {p2, Key}]}]}]
        end, lists:seq(Ts, Ts + NPoints))
    end,
    [begin
        DiffT = NSwimlanes * NSteps * NPtsPerStep,
        Q = if
            DiffT < 2200 ->
                lists:flatten(io_lib:format("select $0, $1 from ~p to ~p end.", [T0, T0 + DiffT]));
            true ->
                lists:flatten(io_lib:format("select count($0), count($1) from ~p to ~p end.", [T0, T0 + min(DiffT, 2500)]))
        end,
        mdhc:log("~s: normal/swimlane: swimlanes = ~p, steps = ~p, points per step = ~p",
            [calendar:system_time_to_rfc3339(erlang:system_time(second)), NSwimlanes, NSteps, NPtsPerStep], true),
        SkipL = [<<"ms">>, <<"mb">>, <<"_qsz">>],
        R1 = without(SkipL, tst_mdhc_6_one(Config, Opts, Qs, NSwimlanes, NSteps, NPtsPerStep, T0, Delay, Wait4Response, PrintResp, DataF, Q, false, infinity)),
        mdhc:log("~s: batch/admin", [calendar:system_time_to_rfc3339(erlang:system_time(second))], true),
        R1 = without(SkipL, tst_mdhc_6_multi(Config, Opts, Qs, NSwimlanes, NSteps, NPtsPerStep, T0, Delay, Wait4Response, PrintResp, DataF, Q, true, infinity)),
        mdhc:log("~s: batch/swimlane", [calendar:system_time_to_rfc3339(erlang:system_time(second))], true),
        R1 = without(SkipL, tst_mdhc_6_multi(Config, Opts, Qs, NSwimlanes, NSteps, NPtsPerStep, T0, Delay, Wait4Response, PrintResp, DataF, Q, false, infinity)),
        mdhc:log("~s: **************", [calendar:system_time_to_rfc3339(erlang:system_time(second))], true),
        ok
    end || {NSwimlanes, NSteps, NPtsPerStep, Delay, Wait4Response, Qs, PrintResp} <- [
            {10, 5, 5, 1000, 5000, [], true},                          % 3x~5s ; 33K/50 data packs; 28K/5 data packs
            {20, 10, 10, 1000, 5000, [{verbose, false}], true}         % 3x~11-20s ; 225K/200 data packs; 200K/10 data packs
        ]
    ],
    ok.

tst_mdhc_6_create_generator(AppKeys = [_ | _], T0, NSteps, NPtsPerStep, DataF, Delay) ->
    {fun
        ({_, _, _, Step}) when Step > NSteps ->
            eof;
        ({T, KeyNo, [Key | Keys], Step}) ->
            Data = DataF(KeyNo, T, NPtsPerStep),
            {ok, Key, Data, case Keys of
                [] ->
                    receive after Delay -> ok end,
                    {T + NPtsPerStep + 1, 1, AppKeys, Step + 1};
                _ ->
                    {T, KeyNo + 1, Keys, Step}
            end}
    end,
    {T0, 1, AppKeys, 1}};

tst_mdhc_6_create_generator(undefined, T0, NSteps, NPtsPerStep, MultiDataF, Delay) ->
    {fun
        ({_, Step}) when Step > NSteps ->
            eof;
        ({T, Step}) ->
            Data = MultiDataF(T, NPtsPerStep),
            receive after Delay -> ok end,
            {ok, Data, {T + NPtsPerStep + 1, Step + 1}}
    end,
    {T0, 1}}.

tst_mdhc_6_one(Config, Opts, Qs, NSwimlanes, NSteps, NPtsPerStep, T0, Delay, WaitResp, _PrintResp, DataF, Q, IsAdmin, Timeout) ->
    {Verbose, SuperClient, AdmClient, Swimlanes} = tst_mdhc_5_create_clients(Config, Opts, NSwimlanes),
    AppKeys = [I#mdhc.app_key || I <- Swimlanes],
    try
        SendFromCli = case IsAdmin of
            true ->
                AdmClient;
            false ->
                hd(Swimlanes)
        end,
        {Generator, GeneratorState} = tst_mdhc_6_create_generator(AppKeys, T0, NSteps, NPtsPerStep, DataF, Delay),
        R1 = mdhc:insert_chunked(SendFromCli, Generator, GeneratorState, Qs, Timeout),
        case R1 of
            {error, req_timedout} ->
                throw(R1);
            _ ->
                mdhc:log("~p", [R1], Verbose)
        end,
        {_, AsyncRequestId} = R1,
        R2 = mdhc:receive_chunked_response(SendFromCli, AsyncRequestId, WaitResp),
        %case PrintResp of
        %    true ->
        %        mdhc:log("Response: ~p", [R2], true);
        %    _ ->
        %        ok
        %end,
        #{<<"batch_size">> := TotalSize, <<"status">> := Status, <<"read_bytes">> := ReadSize} = lists:last(R2),
        mdhc:log("read bytes: ~p, records: ~p, status: ~p", [ReadSize, TotalSize, Status], true),
        Status = 1,
        [mdhc:query(Cli, Q) || Cli <- Swimlanes]
    after
        [#{<<"status">> := 1} = mdhc:delete_appkey(AdmClient, Cli#mdhc.app_key) || Cli <- Swimlanes],
        #{<<"status">> := 1} = mdhc:delete_adminkey(SuperClient, AdmClient#mdhc.admin_key)
    end.

tst_mdhc_6_multi(Config, Opts, Qs, NSwimlanes, NSteps, NPtsPerStep, T0, Delay, WaitResp, PrintResp, DataF, Q, IsAdmin, Timeout) ->
    {Verbose, SuperClient, AdmClient, Swimlanes} = tst_mdhc_5_create_clients(Config, Opts, NSwimlanes),
    try
        MultiDataF = fun (Ts, NPoints) ->
            {D, _} = lists:foldl(fun (Cli, {Acc, No}) ->
                {[[{<<"key">>, Cli#mdhc.app_key}, {<<"data">>, DataF(No, Ts, NPoints)}] | Acc], No + 1}
            end, {[], 1}, Swimlanes),
            D
        end,
        SendFromCli = case IsAdmin of
            true ->
                AdmClient;
            false ->
                hd(Swimlanes)
        end,
        {Generator, GeneratorState} = tst_mdhc_6_create_generator(undefined, T0, NSteps, NPtsPerStep, MultiDataF, Delay),
        R1 = mdhc:insert_chunked(SendFromCli, Generator, GeneratorState, Qs, Timeout),
        case R1 of
            {error, req_timedout} ->
                throw(R1);
            _ ->
                mdhc:log("~p", [R1], Verbose)
        end,
        {_, AsyncRequestId} = R1,
        R2 = mdhc:receive_chunked_response(SendFromCli, AsyncRequestId, WaitResp),
        case PrintResp of
            true ->
                mdhc:log("Response: ~p", [R2], true);
            _ ->
                ok
        end,
        #{<<"batch_size">> := TotalSize, <<"status">> := Status, <<"read_bytes">> := ReadSize} = lists:last(R2),
        mdhc:log("read bytes: ~p, records: ~p, status: ~p", [ReadSize, TotalSize, Status], true),
        Status = 1,
        [mdhc:query(Cli, Q) || Cli <- Swimlanes]
    after
        [#{<<"status">> := 1} = mdhc:delete_appkey(AdmClient, Cli#mdhc.app_key) || Cli <- Swimlanes],
        #{<<"status">> := 1} = mdhc:delete_adminkey(SuperClient, AdmClient#mdhc.admin_key)
    end.

%%--------------------------------------------------------------------
%% compression
%%--------------------------------------------------------------------

tst_mdhc_7(_Config) ->
    tst_mdhc_7_helper(_Config, [
        [],
        [{compression, 'gzip-bson'}],
        [{compression, bson}],
        [{compression, gzip}]
    ]),
    ok.

tst_mdhc_7_helper(_Config, CompressionOptsSet) ->
    ClientOpts = proplists:get_value(mdtsdb_client_opts, _Config),
    Verbose = mdhc:is_trace(#mdhc{options = ClientOpts}),
    mdhc:log("    create an admin client...", [], Verbose),
    Client1 = mdhc:create(?DEF_TEST_HOST, ?DEF_TEST_PORT, ClientOpts),
    %
    mdhc:log("    create a user admin key...", [], Verbose),
    #{<<"key">> := AdmKey1, <<"secret_key">> := SecretAdmKey1} = mdhc:new_adminkey(Client1, <<"User">>),
    Client2Adm = Client1#mdhc{admin_key = AdmKey1, secret_key = SecretAdmKey1},
    mdhc:log("    create a swimlane...", [], Verbose),
    #{<<"key">> := AppKey1, <<"secret_key">> := SecretAppKey1} = mdhc:new_appkey(Client2Adm, <<"UserDetails">>),
    %
    mdhc:log("    prepare data to send...", [], Verbose),
    T0 = mdhc:tnow_lite(),
    SensorData1 = [
        {ns, T0},
        {1, 10},
        {2, 20},
        {3, 2.0},
        {4, 0.2},
        {5, [100, 200, 300]},
        {6, [<<"v1">>, <<"v2">>, <<"v3">>]},
        {7, [1.2, 1.3, 1.4]},
        {8, [1.2, 100, <<"v3">>]}],
    mdhc:log("    send data...", [], Verbose),
    Client2 = Client2Adm#mdhc{app_key = AppKey1, secret_key = SecretAppKey1},
    try
        [#{<<"status">> := 1} = mdhc:insert(Client2, SensorData1, CompressionOpts) || CompressionOpts <- CompressionOptsSet]
    after
        #{<<"status">> := 1} = mdhc:delete_appkey(Client2Adm, Client2#mdhc.app_key),
        L = mdhc:query(Client2Adm, <<"get_swimlanes().">>),
        [mdhc:delete_appkey(Client2Adm, I) || I <- L],
        #{<<"status">> := 1} = mdhc:delete_adminkey(Client1, Client2Adm#mdhc.admin_key)
    end,
    ok.

%%--------------------------------------------------------------------

fql(Fmt, Args) ->
    lists:flatten(io_lib:format(Fmt, Args)).

parse_sql_response(#{<<"data">> := M}, event, Id) when is_map(M) ->
    parse_events(M, Id);

parse_sql_response(#{<<"data">> := R0}, event, Id) ->
    lists:map(fun (M) ->
        if
            is_list(Id) ->
                [parse_events(M, X) || X <- Id];
            true ->
                parse_events(M, Id)
        end
    end, if is_list(R0) -> R0; true -> [R0] end).

parse_events(Props, MeterIds) when is_list(MeterIds) ->
    [parse_events(Props, I) || I <- MeterIds];

parse_events(#{<<"unit">> := IUnit, <<"unit_step">> := IStep, <<"values">> := Values}, MeterId) ->
    MeterIdBin = if
        is_integer(MeterId) ->
            integer_to_binary(MeterId);
        true ->
            MeterId
    end,
    {case maps:get(MeterIdBin, Values) of
        Agg when is_number(Agg) ->
            Agg;
        M when is_map(M) ->
            M
    end, IUnit, IStep}.

test_create_clients(Config) ->
    test_create_clients(Config, [<<"buffer_off">>, <<"autoclean_off">>]).

test_create_clients(Config, Opts) ->
    ClientOpts = proplists:get_value(mdtsdb_client_opts, Config),
    Verbose = mdhc:is_trace(#mdhc{options = ClientOpts}),
    mdhc:log("    create an admin client... ~p", [code:get_path()], Verbose),
    Client0 = mdhc:create(?DEF_TEST_HOST, ?DEF_TEST_PORT, ClientOpts),
    %% apply keycloack auth
    Client1 = test_apply_auth_opts(Client0, Config),
    %%
    mdhc:log("    create a user admin key...", [], Verbose),
    #{<<"key">> := AdmKey1, <<"secret_key">> := SecretAdmKey1} = mdhc:new_adminkey(Client1, <<"Kml Adm User">>),
    Client2Adm = Client0#mdhc{admin_key = AdmKey1, secret_key = SecretAdmKey1},
    mdhc:log("    create a swimlane...", [], Verbose),
    #{<<"key">> := AppKey1, <<"secret_key">> := SecretAppKey1} =
        mdhc:new_appkey(Client2Adm, <<"Swimlane details">>, Opts),
    Client2 = Client2Adm#mdhc{app_key = AppKey1, secret_key = SecretAppKey1},
    {Verbose, Client1, Client2Adm, Client2}.

test_create_clients_raw_response(Config0) ->
    ClientOpts0 = proplists:get_value(mdtsdb_client_opts, Config0),
    ClientOpts = [{response, raw} | ClientOpts0],
    Verbose = mdhc:is_trace(#mdhc{options = ClientOpts}),
    mdhc:log("    create an admin client... ~p", [code:get_path()], Verbose),
    Client0 = mdhc:create(?DEF_TEST_HOST, ?DEF_TEST_PORT, ClientOpts),
    %% apply keycloack auth
    Client1 = test_apply_auth_opts(Client0, Config0),
    %%
    mdhc:log("    create a user admin key...", [], Verbose),
    {ok, #{<<"result">> := #{<<"key">> := AdmKey1, <<"secret_key">> := SecretAdmKey1}}} =
            mdhc:new_adminkey(Client1, <<"Kml Adm User">>),
    Client2Adm = Client0#mdhc{admin_key = AdmKey1, secret_key = SecretAdmKey1},
    mdhc:log("    create a swimlane...", [], Verbose),
    {ok, #{<<"result">> := #{<<"key">> := AppKey1, <<"secret_key">> := SecretAppKey1}}} =
        mdhc:new_appkey(Client2Adm, <<"Swimlane details">>, [<<"buffer_off">>, <<"autoclean_off">>]),
    Client2 = Client2Adm#mdhc{app_key = AppKey1, secret_key = SecretAppKey1},
    {Verbose, Client1, Client2Adm, Client2}.

test_create_temp_cli(Client2Adm) ->
    #{<<"key">> := AppKey, <<"secret_key">> := SecretAppKey} =
        mdhc:new_appkey(Client2Adm, <<"Swimlane details">>, [<<"buffer_off">>, <<"autoclean_off">>]),
    Client2Adm#mdhc{app_key = AppKey, secret_key = SecretAppKey}.

test_apply_auth_opts(Client0, Config) ->
    AuthOpts = proplists:get_value(mdtsdb_auth_opts, Config, []),
    case proplists:get_value(mdtsdb_access_token, AuthOpts, <<>>) of
        <<>> ->
            case proplists:get_value(mdtsdb_auth_url, AuthOpts, <<>>) of
                <<>> ->
                    Client0;
                AuthUrl ->
                    AuthClientId = proplists:get_value(mdtsdb_auth_client_id, AuthOpts, <<>>),
                    AuthClientSecret = proplists:get_value(mdtsdb_auth_client_secret, AuthOpts, <<>>),
                    mdhc:keycloak_set_access_credentials(Client0, AuthUrl, AuthClientId, AuthClientSecret)
            end;
        AccessToken ->
            mdhc:keycloak_set_access_token(Client0, AccessToken)
    end.

%%--------------------------------------------------------------------

l2senddata(_, _, [[] | _], Acc) ->
    lists:reverse(Acc);

l2senddata(T, No, Data = [[_ | _] | _], Acc) ->
    {Data2, {M, _}} = lists:mapfoldl(fun
        ([undefined | Tl], {AccM, AccNo}) ->
            {Tl, {AccM#{integer_to_binary(No) => #{}}, AccNo + 1}};
        ([Hd | Tl], {AccM, AccNo}) ->
            {Tl, {AccM#{integer_to_binary(No) => #{value => Hd}}, AccNo + 1}}
    end, {#{ns => T}, No}, Data),
    l2senddata(T + 1, No, Data2, [M | Acc]).

result2data(D = [{_, _} | _]) ->
    element(2, lists:unzip(D));

result2data(D) ->
    D.

result2data(D, Schema, Alias) ->
    D2 = case parse_sql_response(D, Schema, Alias) of
        [{#{<<"values">> := V}, _, _}] ->
            V;
        [{M, _, _}] ->
            lists:keysort(1, maps:to_list(M))
    end,
    result2data(D2).

without(RL, L) when is_list(L) ->
    case lists:all(fun erlang:is_tuple/1, L) of
        true->
            lists:reverse(lists:foldl(fun
                ({K, V}, Acc) ->
                    case lists:any(fun(El) -> El == K end, RL) of
                        true -> Acc; false -> [{K, without(RL, V)} | Acc]
                    end;
                (V, Acc) ->
                    [V | Acc]
            end, [], L));
        false ->
            [without(RL, V) || V <- L]
    end;

without(RL, M) when is_map(M) ->
    maps:fold(fun (K, V, Acc) ->
        maps:put(K, without(RL, V), Acc)
    end, #{}, maps:without(RL, M));

without(_RL, V) ->
    V.

%%--------------------------------------------------------------------
