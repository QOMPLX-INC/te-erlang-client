-module(texample_app).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

-include_lib("mdtsdbhttpc/include/mdhc.hrl").

-export([without_keycloak/0, with_keycloak/0]).

%% ===================================================================
%% Application callbacks
%% ===================================================================

start(_StartType, _StartArgs) ->
    {ok, _} = application:ensure_all_started(gun),
    {ok, _} = application:ensure_all_started(hackney),
    ok = hackney_pool:start_pool(?MODULE, [{timeout, 120000}, {max_connections, 100}]),
    texample_sup:start_link().

stop(_State) ->
    ok.

%% ===================================================================

create_user(Key, Secret) ->
    mdhc:create("time-engine.qee.qomplxos.com", 443, [
        {use_https, true},
        {httpc, gun},
        {pool, ?MODULE},
        {admin_key, Key},
        {secret_key, Secret}
    ]).

%% Key/Secret authorization
without_keycloak() ->
    SU = create_user(<<"MY_USER_KEY">>, <<"MY_SECRET">>),
    write_and_read(SU).

%% Keycloak authorization
with_keycloak() ->
    SU0 = create_user(<<>>, <<>>),
    AuthClientId = <<"MY_CLIENT_ID">>,
    AuthClientSecret = <<"MY_CLIENT_SECRET">>,
    AuthUrl = <<"KEYCLOAK_AUTH_URL">>,
    SU = mdhc:keycloak_set_access_credentials(SU0, AuthUrl, AuthClientId, AuthClientSecret),
    write_and_read(SU).

%% Sample test case
write_and_read(SU) ->
    #{<<"key">> := AdmKey, <<"secret_key">> := SecretAdmKey} = mdhc:new_adminkey(SU, <<"My User">>),
    User = create_user(AdmKey, SecretAdmKey),
    try
        SwimlaneOpts = #{
            <<"has_expiration">> => true,
            <<"auto_label">> => true
        },
        #{<<"key">> := AppKey, <<"secret_key">> := SecretAppKey} =
            mdhc:new_appkey(User, <<"My Swimlane">>, SwimlaneOpts),
        Swimlane = User#mdhc{admin_key = <<>>, app_key = AppKey, secret_key = SecretAppKey},
        try
            sample_insert(User, AppKey),
            sample_query(Swimlane)
        after
            #{<<"status">> := 1} = mdhc:delete_appkey(User, AppKey, true)
        end
    after
        #{<<"status">> := 1} = mdhc:delete_adminkey(SU, AdmKey)
    end,
    ok.

%% Insert data example
sample_insert(User, AppKey) ->
    Now = erlang:system_time(1),
    Payload = [#{
        <<"key">> => AppKey,
        <<"data">> => [#{
            <<"ns">> => Now,
            <<"0">> => #{<<"value">> => 100},
            <<"1">> => #{<<"value">> => 200}
       }]
    }],
    #{<<"status">> := 1} = mdhc:insert(User, Payload),
    ok.

%% Query data example
sample_query(Swimlane) ->
    L = mdhc:query(Swimlane, <<"select $0-$1 end.">>),
    error_logger:info_msg("Query result: ~p", [L]),
    ok.

%% ===================================================================
