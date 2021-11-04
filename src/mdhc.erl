%%-------------------------------------------------------------------
%%
%% TimeEngine Erlang HTTP Client
%%
%% Copyright 2015-2021 -- QOMPLX, Inc. -- All Rights Reserved.  No License Granted.
%%
%%-------------------------------------------------------------------

%% @doc TimeEngine Erlang HTTP Client.  This module provides access to TimeEngine's
%%      HTTP interface.  For basic usage, please read
%%      <a href="overview-summary.html">the mdtsdbhttpc application overview</a>.
-module(mdhc).

-include("mdhc.hrl").

% Auth mode: 2 - MDTSDB-HMAC-SHA256/MDTSDB-STREAMING-HMAC-SHA256
-define(DEFAULT_AUTH_VERSION, 2).
-define(BEARER_AUTH_VERSION, 3).
-define(MDTSDB_AUTH2, "MDTSDB-HMAC-SHA256 ").
-define(MDTSDB_AUTH2_STREAMING, "MDTSDB-STREAMING-HMAC-SHA256 ").
-define(MDTSDB_AUTH_TOKEN_TYPE, "Bearer ").

-define(DEFAULT_TIMEOUT, 60000).
-define(QL_METHOD_NAME, ql).
-define(WS_METHOD_NAME, ws).
-define(BACK_METHOD_NAME, backend).
-define(WS_CONNECT_TIMEOUT, 30000).

-define(IS_TIMEOUT(Timeout), (Timeout =:= infinity orelse (is_integer(Timeout) andalso Timeout > 0))).

-define(EP_ADMIN,   "api/v1/admin").
-define(EP_INGEST,  "api/v1/ingest").
-define(EP_INGEST2, "api/v1/ingest/").
-define(EP_KML,     "api/v1/ingest/kml").
-define(EP_QL,      "api/v1/ql/").
-define(EP_RESULT,  "api/v1/result").
-define(EP_RESULT2, "api/v1/result/events").

-export([
    start/0, stop/0,
    create/0, create/3,
    % keycloack
    keycloak_set_access_token/2,
    keycloak_set_access_token/3,
    keycloak_set_access_credentials/4,
    keycloak_reload_access_token/1,
    % insert
    insert/2, insert/3, insert/4, insert_geo/2,
    send_kml_file/3, send_kml_data/3,
    % insert chunked
    insert_chunked/3, insert_chunked/5,
    % query
    query/2, query/3,
    % postponed and notifications
    get_stored/2, get_messages/1,
    % admin methods
    new_appkey/2, new_appkey/3, get_or_create_appkey/3, delete_appkey/2, delete_appkey/3,
    new_adminkey/2, get_or_create_adminkey/3, delete_adminkey/2,
    get_opts_admin_key/1, get_opts_app_key/1, get_opts_secret_key/1,
    % websockets
    ws_create/3, ws_close/1, ws_open/1, ws_open/3, ws_adm_open/1, ws_adm_open/3,
    ws_send/2, ws_receive/2, ws_receive/3, ws_parse/2, ws_parse/3,
    % utils
    tnow_lite/0, set_response_format/2,
    receive_chunked_response/2, receive_chunked_response/3, receive_chunked_response/5,
    decoded_chunked_response/3,
    get_stream_errors/1, merge_stream_values/1, merge_stream_values/2, jsonseq_to_json/1,
    %
    % deprecated API methods
    %
    set_options/2,
    send_events_data/2, send_events_data/3, send_events_data/4,
    send_events_data_vector/2, send_events_data_vector/3, send_events_geo_data/2,
    async_send_events_data/3, async_send_events_data/4, async_send_events_data/2,
    ping_events_service/1, ping_events_service/2,
    events_query/2, events_query_sb/2,
    async_events_query/2, async_events_query_sb/2,
    events_query/3, events_query_sb/3,
    async_events_query/3, async_events_query_sb/3,
    send_events_data_chunked/3, send_events_data_chunked/5
]).

% internal api
-export([
    is_trace/1, is_profile/1, log/3,
    is_keycloak_auth_error/2
]).

-export_type([mdhc/0]).
-opaque mdhc() :: #mdhc{}.

%%-------------------------------------------------------------------

%% @doc Starts the Application
-spec start() -> {ok, [atom()]} | {error, term()}.
start() ->
    {ok, _} = application:ensure_all_started(mdtsdbhttpc).

%% @doc Stops the Application
-spec stop() -> ok | {error, term()}.
stop() ->
    ok = application:stop(mdtsdbhttpc).

%%-------------------------------------------------------------------
%% API

%% @doc Create a client for connecting to the default port on localhost.
%% @equiv create("127.0.0.1", 8080, [])
create() ->
    create("127.0.0.1", 8080, []).

%% @doc Create a client for connecting to a TimeEngine node.
%%
%%      Connections will be made to:
%%      ```http://IP:Port/Resource[/<key>]''' or ```https://IP:Port/Resource[/<key>]'''
%%
%%      The application key (if already exists), the secret key (always needed) and
%%      the admin key (if needed) should be specified by adding `{app_key, AppKey}',
%%      `{secret_key, SecretKey}' and `{admin_key, AdminKey}' to the Options list.
%%      Keys are binary().
%%
%%     Available options:
%%         use_https :: boolean       - use HTTPS scheme
%%         async_response :: boolean  - request returns {ibrowse_req_id, RequestId} or {hackney_req_id, RequestId}
%%                                      instead of the response body, and the http client fetches the response
%%                                      asynchronously and sends content as messages to the caller process;
%%                                      async response can be received and decoded using helper functions:
%%                                      receive_chunked_response() and decoded_chunked_response();
%%                                      default is true for chunked transfer encoding, false otherwise
%%         auth_mode :: 1 | 2         - temporary switch to select authentication method (1 - legacy, 2 - future standard);
%%                                      default is 2
%%         httpc :: gun | hackney     - selection of the httpc client, mandatory option
%%         pool :: atom()             - pool size of the httpc client
%%         timeout :: integer()       - default timeout of the httpc client if not overrided by the request
%%         response :: lists | maps   - select how to decode and represent json
%%         trace :: boolean()         - verbose output log
%%         app_key :: binary()        - swimlane/application key
%%         admin_key :: binary()      - user/admin key
%%         secret_key :: binary()     - secret key of the key that is used to sign requests
%%
%% @spec create(string(), integer(), Options::list()) -> mdhc()
create(IP, Port, Opts) when is_list(IP), is_integer(Port), is_list(Opts) ->
    #mdhc{
        ip = IP,
        port = Port,
        app_key = get_binary_option(Opts, app_key, <<>>),
        secret_key = get_binary_option(Opts, secret_key, <<>>),
        admin_key = get_binary_option(Opts, admin_key, <<>>),
        options = Opts}.

%% @doc Setup keycloak access token.
%%
%%      Setup keycloak access token.
%%
%% @spec keycloak_set_access_token(Client :: mdhc(), Token :: binary()) -> mdhc().
keycloak_set_access_token(Mdhc, Token) when is_binary(Token) ->
    keycloak_set_access_token(Mdhc, Token, <<?MDTSDB_AUTH_TOKEN_TYPE>>).

%%-------------------------------------------------------------------
%% keycloack authorization

%% @doc Setup keycloak access token.
%%
%%      Setup keycloak access token.
%%
%% @spec keycloak_set_access_token(Client :: mdhc(), Token :: binary(), TokenType :: binary()) -> mdhc().
keycloak_set_access_token(Mdhc, Token, TokenType) when is_binary(Token), is_binary(TokenType) ->
    Opts0 = Mdhc#mdhc.options,
    Opts1 = process_access_token(Token, Opts0),
    Mdhc#mdhc{
        access_token = Token,
        access_token_type = TokenType,
        app_key = get_binary_option(Opts1, app_key, <<>>),
        secret_key = get_binary_option(Opts1, secret_key, <<>>),
        admin_key = get_binary_option(Opts1, admin_key, <<>>),
        options = Opts1}.

%% @doc Setup keycloak access credentials.
%%
%%      Setup keycloak access credentials.
%%
%% @spec keycloak_set_access_credentials(Client :: mdhc(), AuthUrl :: binary(), ClientId :: binary(), ClientSecret :: binary()) -> mdhc().
keycloak_set_access_credentials(Mdhc, AuthUrl, ClientId, ClientSecret) when is_binary(AuthUrl), is_binary(ClientId), is_binary(ClientSecret) ->
    keycloak_reload_access_token(Mdhc#mdhc{auth_url = AuthUrl, auth_client_id = ClientId, auth_client_secret = ClientSecret}).

%% @doc Reload keycloak access token.
%%
%%      Reload keycloak access token.
%%
%% @spec keycloak_load_access_token(Client :: mdhc(), AuthUrl :: binary(), ClientId :: binary(), ClientSecret :: binary()) -> mdhc().
keycloak_reload_access_token(Mdhc = #mdhc{auth_url = AuthUrl, auth_client_id = ClientId, auth_client_secret = ClientSecret})
        when AuthUrl == <<>>; ClientId == <<>>; ClientSecret == <<>> ->
    Mdhc;
keycloak_reload_access_token(Mdhc = #mdhc{auth_url = AuthUrl, auth_client_id = ClientId, auth_client_secret = ClientSecret}) ->
    Headers = [
        {"Content-Type", "application/x-www-form-urlencoded"},
        {"cache-control", "no-cache"}
    ],
    Body = <<"client_id=", ClientId/binary, "&client_secret=", ClientSecret/binary, "&grant_type=client_credentials">>,
    Response = gun_request(post, AuthUrl, Headers, Body, [{connect_timeout, 5000}]),
    case Response of
        {ok, 200, _Headers, RespBody} ->
            RespObj = jsx:decode(RespBody, [return_maps]),
            keycloak_reload_access_token_helper(Mdhc, RespObj);
        {ok, _Code, _Headers, RespErr} -> 
            throw(RespErr)
    end.

keycloak_reload_access_token_helper(Mdhc, RespObj) ->
    Token = maps:get(<<"access_token">>, RespObj, <<>>),
    TokenType = case RespObj of
        #{<<"token_type">> := TokenType0} ->
            case binary:last(TokenType0) of
                32 -> TokenType0; _ -> <<TokenType0/binary, 32>>
            end;
        _ ->
            <<?MDTSDB_AUTH_TOKEN_TYPE>>
    end,
    case Token of
        <<>> ->
            throw("unexpected responce: undefined 'access_token'");
        _ ->
            keycloak_set_access_token(Mdhc, Token, TokenType)
    end.

%%-------------------------------------------------------------------
%% Insert

%% @doc Uploads data from sensors to server.
%%
%%      There are two modes of the method: batch multi-swimlane send and one-swimlane send.
%%      In the one-swimlane send data swimline is determined by the application key of the client.
%%      Several time points can be sent at once, either in a zipped list tuples
%%          ```{Timestamp, SensorData}'''
%%      where Timestamp is a Unix timestamp and SensorData argument has the same format
%%      as in send_streaming_data/2, or in a list of lists, where each item holds both
%%      a timestamp and sensor values, e.g.:
%%          ```[[{ns, 1421507438}, {3, 30}], [{ns, 1421507439}, {1, 10}, {2, 20}]]'''
%%
%%      In the case of batch multi-swimlane send, the application key of the client is used only
%%      for authentication. Destination swimlanes are listed in the method 'params' field.
%%      Sensor data must be formatted as the following:
%%      ```[{'key': 'swimlane1', 'data': ...}, {'key': 'swimlane2', 'data': ...}, ...]'''
%%      where 'data' format is the same as sensor data for one-swimlane send data version of the method.
%%
%%      This method can be called by admin client, so that admin key/secret key are used for authentication.
%%      Only batch multi-swimlane send is available for sending data by the admin client.
%%
%%      Sensor value is either scalar value (numeric or binary string), or the json object encoded
%%      in jsx:encode() format.
%% @spec insert(Client :: mdhc(), SensorData :: list()) ->
%%              Properties :: list() | {error, Reason :: term()}
insert(Mdhc, SensorData) ->
    insert(Mdhc, SensorData, [], []).

insert(Mdhc, SensorData, QueryOpts) ->
    insert(Mdhc, SensorData, QueryOpts, []).

insert(Mdhc, SensorData, QueryOpts, ReqOpts) ->
    RpcArgs = #{
        method => setData,
        context => events,
        key => Mdhc#mdhc.app_key,
        opts => QueryOpts,
        params => send_data_genparams(SensorData)
    },
    call_method(Mdhc, setData, [{mode, events}], case Mdhc#mdhc.app_key of
        <<>> ->
            RpcArgs#{adminkey => Mdhc#mdhc.admin_key};
        _ ->
            RpcArgs
    end, ReqOpts).

%% @doc Uploads data from sensors to server
%%      using the chunked transfer encoding.
%%
%% @spec insert_chunked(Client :: mdhc(),
%%                      SensorData :: fun((term()) -> {ok, binary(), list()} |
%%                                                    {ok, binary(), list(), term()} |
%%                                                    {ok, list()} |
%%                                                    {ok, list(), term()} |
%%                                                    term()),
%%                      GeneratorState :: term()) ->
%%                      Properties :: list() | {error, Reason :: term()}
insert_chunked(Mdhc, SensorData, GeneratorState) ->
    send_data_chunked(events, Mdhc, SensorData, GeneratorState, [], undefined).

%% @doc Uploads data from sensors to server using an 'events' mode
%%      using the chunked transfer encoding.
%%
%% @spec insert_chunked(Client :: mdhc(),
%%                      SensorData :: fun((term()) -> {ok, binary(), list()} |
%%                                                    {ok, binary(), list(), term()} |
%%                                                    {ok, list()} |
%%                                                    {ok, list(), term()} |
%%                                                    term()),
%%                      GeneratorState :: term(),
%%                      Options :: list(),
%%                      Timeout :: positive_integer() | infinity) ->
%%                      Properties :: list() | {error, Reason :: term()}
insert_chunked(Mdhc, SensorData, GeneratorState, Options, Timeout) when ?IS_TIMEOUT(Timeout) ->
    send_data_chunked(events, Mdhc, SensorData, GeneratorState, Options, Timeout).

send_data_chunked(Mode, Mdhc, Generator, InitGeneratorState, Opts, MaybeTimeout) ->
    RpcArgs0 = #{
        method => setData,
        context => Mode,
        key => Mdhc#mdhc.app_key,
        opts => []
    },
    RpcArgs = case Mdhc#mdhc.app_key of
        <<>> ->
            RpcArgs0#{adminkey => Mdhc#mdhc.admin_key};
        _ ->
            RpcArgs0
    end,
    MethodArgs = if
        ?IS_TIMEOUT(MaybeTimeout) ->
            [{timeout, MaybeTimeout}, {mode, Mode} | Opts];
        true ->
            [{mode, Mode} | Opts]
    end,
    call_method(Mdhc, setData, MethodArgs, {fun (GeneratorState0) ->
        case Generator(GeneratorState0) of
            {ok, AppKey, SensorData, GeneratorState} when is_binary(AppKey), is_list(SensorData) ->
                Content = jsx:encode(RpcArgs#{key => AppKey, params => send_data_genparams(SensorData)}),
                {ok, Content, GeneratorState};
            {ok, AppKey, SensorData} when is_binary(AppKey), is_list(SensorData) ->
                Content = jsx:encode(RpcArgs#{key => AppKey, params => send_data_genparams(SensorData)}),
                {ok, Content, GeneratorState0};
            {ok, SensorData, GeneratorState} when is_list(SensorData) ->
                Content = jsx:encode(RpcArgs#{params => send_data_genparams(SensorData)}),
                {ok, Content, GeneratorState};
            {ok, SensorData} when is_list(SensorData) ->
                Content = jsx:encode(RpcArgs#{params => send_data_genparams(SensorData)}),
                {ok, Content, GeneratorState0};
            _ ->
                eof
        end
    end, InitGeneratorState}).

%% @spec insert_geo(Client :: mdhc(), GeoData :: binary()) ->
%%          Properties :: list() | {error, Reason :: term()}
insert_geo(Mdhc, GeoData) ->
    call_method(Mdhc, setData, [{mode, geo_events}], GeoData).

%% @doc Uploads file in Keyhole Markup Language (KML/KMZ) format.
%%
%%      Opts list may hold several key-value records with predefined names to
%%      fill possible gaps in geo-information in KML format on server side.
%%
%%      Available keys are:
%%
%%      'alias_tag' to identify KML tag to find sensor identifier (alias), 'name' by default;
%%      'id' for default sensor identifier, e.g., 'id': '0';
%%
%%      'val_tag' to identify KML tag where server should find sensor value at the given moment of time,
%%      ('description' by default), e.g., val_tag: 'value';
%%      'val' for default sensor value at the given moment of time, 'null' by default;
%%
%%      'ms_tag' to identify KML tag with a timestamp to use with the KML record, e.g., ms_tag: 'TimeStamp';
%%      'ms_attr' to identify attribute of the 'placemark' KML tag with a timestamp to use with the KML record,
%%      e.g., ms_attr: 'id';
%%      'ns' for default timestamp (nanosecond) of the sent data, e.g., 'ns': 1421299624000000000.
%%
%%      All these records are used in case when server cannot derive such information
%%      (id, timestamp, value, etc.) from fields of sent KML data set. Use of 'ms_tag' and 'ms_attr' options
%%      is mutually exclusive, 'ms_tag' has priority if both options are given.
%%
%%      Please note that if several data points in the KML data set miss sensor id and
%%      timestamp information, the server will use identical default id/timestamp values
%%      for all such points. Since only one data point can be stored for each pair of
%%      (sensor identifier, timestamp), only one data point from such data set will be
%%      actually stored as the result of the collision.
%%
%% @spec send_kml_file(Client :: mdhc(), KmlFilePath :: string() | binary(), Opts :: list()) ->
%%                     Properties :: list() | {error, Reason :: term()}
send_kml_file(Mdhc, FilePath, Opts) ->
    case file:read_file(FilePath) of
        {ok, Content} ->
            send_kml_data(Mdhc, Content, Opts);
        Error ->
            Error
    end.

%% @doc Uploads data in Keyhole Markup Language (KML/KMZ) format.
%%
%%      Opts list may hold several key-value records with predefined names to
%%      fill possible gaps in geo-information in KML format on server side.
%%
%%      Available keys are:
%%
%%      'alias_tag' to identify KML tag to find sensor identifier (alias), 'name' by default;
%%      'id' for default sensor identifier, e.g., 'id': '0';
%%
%%      'val_tag' to identify KML tag where server should find sensor value at the given moment of time,
%%      ('description' by default), e.g., val_tag: 'value';
%%      'val' for default sensor value at the given moment of time, 'null' by default;
%%
%%      'ms_tag' to identify KML tag with a timestamp to use with the KML record, e.g., ms_tag: 'TimeStamp';
%%      'ms_attr' to identify attribute of the 'placemark' KML tag with a timestamp to use with the KML record,
%%      e.g., ms_attr: 'id';
%%      'ns' for default timestamp (unix second) of the sent data, e.g., 'ns': 1421299624000000000.
%%
%%      All these records are used in case when server cannot derive such information
%%      (id, timestamp, value, etc.) from fields of sent KML data set. Use of 'ms_tag' and 'ms_attr' options
%%      is mutually exclusive, 'ms_tag' has priority if both options are given.
%%
%%      Please note that if several data points in the KML data set miss sensor id and
%%      timestamp information, the server will use identical default id/timestamp values
%%      for all such points. Since only one data point can be stored for each pair of
%%      (sensor identifier, timestamp), only one data point from such data set will be
%%      actually stored as the result of the collision.
%%
%% @spec send_kml_data(Client :: mdhc(), Content :: binary(), Opts :: list()) ->
%%                Properties :: list() | {error, Reason :: term()}
send_kml_data(Mdhc, Content, Opts0) when is_binary(Content) ->
    Opts = lists:filter(fun
        ({id, DefAlias}) when is_number(DefAlias); is_list(DefAlias) ->
            true;
        ({alias_tag, TagAlias}) when is_atom(TagAlias); is_list(TagAlias) ->
            true;
        ({ns, Ms}) when is_integer(Ms), Ms >= 0 ->
            true;
        ({ms_attr, MsAttr}) when is_atom(MsAttr); is_list(MsAttr) ->
            true;
        ({ms_tag, MsTag}) when is_atom(MsTag); is_list(MsTag) ->
            true;
        ({val, DefVal}) when is_number(DefVal); is_atom(DefVal); is_list(DefVal) ->
            true;
        ({val_tag, ValTag}) when is_atom(ValTag); is_list(ValTag) ->
            true;
        ({base64, IsBase64}) when is_boolean(IsBase64) ->
            true;
        (_) ->
            false
    end, Opts0),
    kml_query(Mdhc, [{mode, kml}], Content, Opts).

%%-------------------------------------------------------------------
%% Query

%% @spec query(Client :: mdhc(), Script :: string()) ->
%%                          Result :: list() | binary() | integer() |
%%                          {error, Reason :: term()} |
%%                          {postpone, Uuid :: integer() | binary()}
query(Mdhc, Script) ->
    ql_query(Mdhc, [{mode, events}, {ver, 2}], Script).

%% @spec query(Client :: mdhc(), Script :: string(), Opts :: list()) ->
%%                          Result :: list() | binary() | integer() |
%%                          {error, Reason :: term()} |
%%                          {postpone, Uuid :: integer() | binary()}
query(Mdhc, Script, Opts) ->
    ql_query(Mdhc, [{mode, events}, {ver, 2} | Opts], Script).

%%-------------------------------------------------------------------
%% Postponed and notifications

%% @doc Queries data, which were stored after delayed execution of the query.
%%
%%      "Uuid" - identifier of the stored data, as returned in details of the
%%               response with notification about delayed execution, e.g.:
%%               ```"error": {"message": "the job is postponed", "details": {"code": 12001, "uuid": 12345}}'''
%%
%%
%% @spec get_stored(Client :: mdhc(), Uuid :: integer() | binary()) ->
%%                          Result :: list() | binary() | integer() | {error, Reason :: term()}
get_stored(Mdhc, Uuid) when is_integer(Uuid); is_binary(Uuid) ->
    delayed_query(Mdhc, [{mode, results}], Uuid).

%% @doc Queries TimeEngine for Error/Warning diagnostic messages about possible
%%      problems which could happen while data storing and indexing if a user
%%      has defined a list of indexes/incremental aggregation methods and this
%%      list does not conform with the actual data sent to the TimeEngine service.
%%
%% @spec get_messages(Client :: mdhc()) ->
%%                          Result :: list() | binary() | integer() | {error, Reason :: term()}
get_messages(Mdhc) ->
    delayed_query(Mdhc, [{mode, events_results}], <<>>).

%%-------------------------------------------------------------------
%% Admin methods

%% @doc Sends additional details of sensors nature (labels, geo-position, etc.).
%%
%%      The SensorOptions argument is the list of fields of the json object encoded
%%      in jsx:encode() format. It can contain any of the following fields:
%%
%%      "geo_scale" - default map scale for geo-hashing/geo-queries, e.g., ```{geo_scale, 20}'''
%%      "stationary" - coordinates for sensors which have known fixed position
%%                     (stationary sensors), e.g.,
%%      ```{stationary, [{90, [{lat, 40}, {lng, 30}]}]}'''
%%      "labels" - aliases of sensors to use in json/text reports of sensor data, e.g.
%%      ```{labels, [{90, alias90}]}'''
%%      "aggregation" - aggregation methods of sensors to use when data for the same unix timestamp
%%                      arrives, or when seconds data are aggregated to minutes, and further to hours, e.g.
%%      ```{aggregation, [{90, sum}]}'''
%% @spec set_options(Client :: mdhc(), SensorOptions :: list()) ->
%%                          Properties :: list() | {error, Reason :: term()}
set_options(Mdhc, SensorProps) ->
    call_method(Mdhc, setOptions, [], jsx:encode(#{
        method => setOptions,
        key => Mdhc#mdhc.app_key,
        params => SensorProps
    })).

%% @doc Creates a new application key. Requires an admin key.
%% @spec new_appkey(Client :: mdhc(), UserInfo :: binary()) ->
%%                          Properties :: list() | {error, Reason :: term()}
new_appkey(Mdhc, UserInfo) ->
    new_appkey(Mdhc, UserInfo, []).

%% @doc Creates a new application key. Requires an admin key.
%% @spec new_appkey(Client :: mdhc(), UserInfo :: binary(), KeyOpts :: map() | list()) ->
%%                          Properties :: list() | {error, Reason :: term()}
new_appkey(Mdhc, UserInfo, KeyOpts) ->
    call_method(Mdhc, newApiKey, [], jsx:encode(#{
        method => newApiKey,
        params => #{
            adminkey => Mdhc#mdhc.admin_key,
            opts => KeyOpts,
            user => UserInfo
        }
    })).

%% @doc Read secret key of existing application key or creates a new application key. Requires an admin key.
%%
%% Field "suggest" in the parameter "KeyOpts" is the application key to get or create.
%% Returns secret key if app key exists and belongs to the admin key that executes the request.
%% Returns error if existing app key belongs to another admin key.
%% Creates a new application key if there is no app key with such name.
%%
%% @spec get_or_create_appkey(Client :: mdhc(), UserInfo :: binary(), KeyOpts :: map() | list()) ->
%%                            Properties :: list() | {error, Reason :: term()}
get_or_create_appkey(Mdhc, UserInfo, KeyOpts) ->
    call_method(Mdhc, assureApiKey, [], jsx:encode(#{
        method => assureApiKey,
        params => #{
            adminkey => Mdhc#mdhc.admin_key,
            opts => KeyOpts,
            user => UserInfo
        }
    })).

%% @doc Deletes the application key. Requires an admin key.
%%
%% The administrator key must be the same key that was used to create the application key.
%% @spec delete_appkey(Client :: mdhc(), AppKey :: binary()) ->
%%                          Properties :: list() | {error, Reason :: term()}
delete_appkey(Mdhc, AppKey) ->
    delete_appkey0(Mdhc, deleteApiKey, #{
        adminkey => Mdhc#mdhc.admin_key,
        key => AppKey
    }).

%% @doc Deletes the application key. Requires an admin key.
%%
%%      The administrator key must be the same key that was used to create the application key.
%% @spec delete_appkey(Client :: mdhc(), AppKey :: binary(), KeepData :: boolean()) ->
%%                          Properties :: list() | {error, Reason :: term()}
delete_appkey(Mdhc, AppKey, KeepData) when is_boolean(KeepData) ->
    delete_appkey0(Mdhc, deleteApiKey, #{
        adminkey => Mdhc#mdhc.admin_key,
        key => AppKey,
        keep_data => KeepData
    }).

delete_appkey0(Mdhc, Method, Params) ->
    call_method(Mdhc, Method, [], jsx:encode(#{
        method => Method,
        params => Params
    })).

%% @doc Creates a new admin key. Requires an admin key with super-user rights.
%%
%% @spec new_adminkey(Client :: mdhc(), UserInfo :: binary()) ->
%%                          Properties :: list() | {error, Reason :: term()}
new_adminkey(Mdhc, UserInfo) ->
    call_method(Mdhc, newAdminKey, [], jsx:encode(#{
        method => newAdminKey,
        params => #{
            adminkey => Mdhc#mdhc.admin_key,
            user => UserInfo
        }
    })).

%% @doc Read secret key of existing admin key or creates a new admin key. Requires an admin key with super-user rights.
%%
%% Returns secret key if admin key exists, otherwise creates a new admin key.
%%
%% @spec get_or_create_adminkey(Client :: mdhc(), AdmKey :: binary(), UserInfo :: binary()) ->
%%                              Properties :: list() | {error, Reason :: term()}
get_or_create_adminkey(Mdhc, AdmKey, UserInfo) ->
    call_method(Mdhc, assureAdminKey, [], jsx:encode(#{
        method => assureAdminKey,
        params => #{
            adminkey => Mdhc#mdhc.admin_key,
            suggest => AdmKey,
            user => UserInfo
        }
    })).

%% @doc Deletes the admin key. Requires an admin key with super-user rights.
%%
%% @spec delete_adminkey(Client :: mdhc(), AdminKey2Delete :: binary()) ->
%%                              Properties :: list() | {error, Reason :: term()}
delete_adminkey(Mdhc, AdminKey2Delete) ->
    call_method(Mdhc, deleteAdminKey, [], jsx:encode(#{
        method => deleteAdminKey,
        params => #{
            adminkey => Mdhc#mdhc.admin_key,
            key => AdminKey2Delete
        }
    })).

%%-------------------------------------------------------------------
%% Websockets

%% @doc Update client with a new web socket connection without admin access.
%%
%% @spec ws_open(Client :: mdhc()) ->
%%                  {ok, UpdatedClient :: mdhc()} | {error, Reason :: term()}
ws_open(Mdhc) ->
    ws_open(Mdhc, undefined, ?WS_CONNECT_TIMEOUT).

%% @doc Update client with a new web socket connection without admin access.
%% Timeout is either maximum number of milliseconds to wait, or 'infinity'.
%%
%% @spec ws_open(Client :: mdhc(), Async :: boolean() | undefined, Timeout :: infinity | integer()) ->
%%                  {ok, UpdatedClient :: mdhc()} | {error, Reason :: term()}
ws_open(Mdhc, Async, Timeout) ->
    ws_open0(Mdhc#mdhc{admin_key = <<>>}, Async, Timeout).

%% @doc Update client with a new web socket connection with admin access. Requires an admin key.
%% @spec ws_adm_open(Client :: mdhc()) ->
%%                      {ok, UpdatedClient :: mdhc()} | {error, Reason :: term()}
ws_adm_open(Mdhc) ->
    ws_adm_open(Mdhc, undefined, ?WS_CONNECT_TIMEOUT).

%% @doc Update client with a new web socket connection with admin access. Requires an admin key.
%% @spec ws_adm_open(Client :: mdhc(), Async :: boolean() | undefined, Timeout :: infinity | integer()) ->
%%                      {ok, UpdatedClient :: mdhc()} | {error, Reason :: term()}
ws_adm_open(Mdhc = #mdhc{admin_key = AdmKey}, Async, Timeout) when is_binary(AdmKey), AdmKey /= <<>> ->
    ws_open0(Mdhc, Async, Timeout).

ws_open0(Mdhc, Async, Timeout) ->
    case ws_create(Mdhc, Async, Timeout) of
        {ok, WsConnPid, WsStreamRef} ->
            {ok, Mdhc#mdhc{ws = WsConnPid, ws_stream = WsStreamRef}};
        R ->
            R
    end.

%% @doc Close web socket connection.
%% @spec ws_close(Client :: mdhc() | pid()) -> ok
%%
ws_close(#mdhc{ws = WsConnPid, ws_stream = WsStreamRef}) ->
    ws_close(WsConnPid, WsStreamRef).

ws_close(undefined, _) ->
    ok;

ws_close(WsConnPid, WsStreamRef) when is_pid(WsConnPid) ->
    gun:ws_send(WsConnPid, WsStreamRef, close),
    gun:shutdown(WsConnPid),
    ok.

%% @doc Creates a new web socket connection.
%%
%% @spec ws_create(Client :: mdhc(), Async :: boolean() | undefined, Timeout :: infinity | integer()) ->
%%                  {ok, WsConnPid :: pid(), WsStreamRef :: reference()} | {error, Reason :: term()}
ws_create(Mdhc, Async, Timeout) when ?IS_TIMEOUT(Timeout) ->
    AsyncParam = case Async of
        true ->
            <<"async=true">>;
        false ->
            <<"async=false">>;
        _ ->
            <<>>
    end,
    {Endpoint, SignKey} = case {Mdhc#mdhc.admin_key, Mdhc#mdhc.app_key} of
        {<<>>, UserKey} ->
            {lists:flatten(io_lib:format("api/v1/ws/~s~s", [UserKey, maybe_prepend($?, AsyncParam)])), UserKey};
        {AdmKey, <<>>} ->
            {lists:flatten(io_lib:format("api/v1/ws/~s~s", [AdmKey, maybe_prepend($?, AsyncParam)])), AdmKey};
        {AdmKey, UserKey} ->
            {lists:flatten(io_lib:format("api/v1/ws/~s?key=~s~s", [AdmKey, UserKey, maybe_prepend($&, AsyncParam)])), AdmKey}
    end,
    {_, AuthHeader} = make_auth_header(Mdhc, SignKey, ?WS_METHOD_NAME, list_to_binary(Endpoint), undefined, <<>>),
    {ok, ConnPid} = gun:open(Mdhc#mdhc.ip, Mdhc#mdhc.port, #{protocols => [http]}),
    {ok, _R} = gun:await_up(ConnPid),
    StreamRef = gun:ws_upgrade(ConnPid, [$/ | Endpoint], [
        {"Authorization", AuthHeader}
    ]),
    receive
        {gun_upgrade, ConnPid, StreamRef, [<<"websocket">>], _} ->
            {ok, ConnPid, StreamRef};
        {gun_response, ConnPid, _, _, Status, _} ->
            {error, Status};
        {gun_error, ConnPid, _, Reason} ->
            {error, Reason}
    after
        Timeout ->
            {error, timeout}
    end.

%% @doc Parse response received from websocket.
%%
%% @spec ws_send(Client :: mdhc(), Frame :: binary()) -> ok
ws_send(Mdhc = #mdhc{}, Frame) when is_map(Frame) ->
    ws_send(Mdhc, jsx:encode(Frame));

ws_send(Mdhc = #mdhc{ws = WsConnPid, ws_stream = WsStreamRef}, Frame) when is_binary(Frame) ->
    case is_trace(Mdhc) of
        true ->
            log("ws_send(): ~p", [Frame]);
        _ ->
            ok
    end,
    gun:ws_send(WsConnPid, WsStreamRef, {text, Frame}).

%% @doc Parse response received from websocket.
%%
%% @spec ws_receive(Client :: mdhc(), Timeout :: infinity | integer()) -> mdhc_ws_resp()
ws_receive(Mdhc, Timeout) ->
    ws_receive(Mdhc, Timeout, false).

%% @doc Parse response received from websocket.
%%
%% @spec ws_receive(Client :: mdhc(), Timeout :: infinity | integer(), Stream :: boolean()) -> mdhc_ws_resp()
ws_receive(#mdhc{ws = undefined}, _Timeout, _Stream) ->
    {error, undefined, disconnected};

ws_receive(Mdhc, Timeout, false) ->
    ws_receive_frame(Mdhc, Timeout, is_trace(Mdhc));

ws_receive(Mdhc, Timeout, true) ->
    ws_receive_streambody(Mdhc, Timeout, is_trace(Mdhc), <<>>).

ws_receive_frame(#mdhc{ws = WsConnPid, ws_stream = WsStreamRef}, Timeout, _Verbose) ->
    receive
        {gun_ws, WsConnPid, WsStreamRef, {text, Frame}} ->
            Frame
    after
        Timeout ->
            {error, undefined, timeout}
    end.

ws_receive_streambody(Mdhc, Timeout, Verbose, Acc) ->
    case ws_receive_frame(Mdhc, Timeout, Verbose) of
        {error, undefined, timeout} ->
            {error, undefined, timeout};
        <<16#1e, 10>> ->
            Acc;
        Frame ->
            ws_receive_streambody(Mdhc, Timeout, Verbose, <<Acc/binary, Frame/binary>>)
    end.

%% @doc Parse response received from websocket.
%%
%% @spec ws_parse(Client :: mdhc() | pid(), Payload :: {text, binary()} | binary()) -> mdhc_ws_resp()

ws_parse(Mdhc, Frame) ->
    ws_parse(Mdhc, Frame, #{}).


ws_parse(Mdhc, Frame, Opts) when is_list(Opts) ->
    ws_parse(Mdhc, Frame, maps:from_list(Opts));

ws_parse(Mdhc, {text, Frame}, Opts) ->
    ws_parse(Mdhc, Frame, Opts);

ws_parse(Mdhc = #mdhc{}, Frame, Opts) when is_binary(Frame) ->
    Format = get_response_format(Mdhc),
    Verbose = is_trace(Mdhc),
    JsxOpts = case Format of
        lists ->
            [];
        _ ->
            [return_maps]
    end,
    try
        case Opts of
            #{stream := true} ->
                Lines0 = binary:split(Frame, <<16#1e>>, [global, trim_all]),
                Lines = [read_body_ltrim(Line) || Line <- Lines0],
                lists:reverse(lists:foldl(fun(Line, Acc) ->
                    try
                        [parse_result(jsx:decode(Line, JsxOpts), size(Line), Format, Verbose) | Acc]
                    catch
                        error:badarg ->
                            Acc
                    end
                end, [], Lines));
            _ ->
                ws_format_response(jsx:decode(Frame, JsxOpts), Format)
        end
    catch
        error:badarg ->
            case Opts of
                #{stream := true} ->
                    [Frame];
                _ ->
                    Frame
            end
    end;

ws_parse(_, {error, _, timeout}, _) ->
    {error, undefined, timeout};

ws_parse(_, _, _) ->
    {error, undefined, unknown_format}.

ws_format_response(R, raw) ->
    {ok, undefined, R};

ws_format_response(L, lists) when is_list(L) ->
    Id = proplists:get_value(<<"id">>, L, undefined),
    case proplists:lookup(<<"error">>, L) of
        {_, Props} ->
            {_, Message} = proplists:lookup(<<"message">>, Props),
            {error, Id, Message};
        none ->
            case proplists:lookup(<<"result">>, L) of
                {_, Result} ->
                    {ok, Id, Result};
                none ->
                    {ok, undefined, L}
            end
    end;

ws_format_response(#{<<"id">> := Id, <<"result">> := Result}, _) ->
    {ok, Id, Result};

ws_format_response(#{<<"id">> := Id, <<"error">> := #{<<"message">> := Message}}, _) ->
    {error, Id, Message};

ws_format_response(R, _) ->
    {ok, undefined, R}.

%%-------------------------------------------------------------------
%% API: Utils

%% @doc Returns unix timestamp.
%% @spec tnow_lite() -> UnixTimestamp :: integer()
tnow_lite() ->
    {Mega, Secs, _} = os:timestamp(),
    Mega * 1000000 + Secs.

%% @doc Receive and decodes async chunked response.
%% @spec receive_chunked_response(Client :: mdhc(), Timeout :: integer()) -> [OneResponse :: term()]
receive_chunked_response(Mdhc, Timeout) ->
    receive_chunked_response0(Mdhc, undefined, Timeout, #{}, true, is_trace(Mdhc)).

%% @doc Receive and decodes async chunked response.
%% @spec receive_chunked_response(Client :: mdhc(), ReqId :: term(), Timeout :: integer()) -> [OneResponse :: term()]
receive_chunked_response(Mdhc, ReqId, Timeout) ->
    receive_chunked_response0(Mdhc, ReqId, Timeout, #{}, true, is_trace(Mdhc)).

%% @doc Receive and decodes async chunked response.
%% @spec receive_chunked_response(Client :: mdhc(), ReqId :: term(), Timeout :: integer(),
%%                                ServiceEvents :: boolean(), Verbose :: boolean()) ->
%%                                    [OneResponse :: 'timeout' | term()]
receive_chunked_response(Mdhc, ReqId, Timeout, ServiceEvents, Verbose) ->
    receive_chunked_response0(Mdhc, ReqId, Timeout, #{}, ServiceEvents, Verbose).

receive_chunked_response0(Mdhc, ReqId, Timeout, Acc, ServiceEvents, Verbose) ->
    receive
        {gun_response, _ConnPid, ReqId, _, RespStatus, RespHeaders} ->
            Acc2 = if
                ServiceEvents ->
                    maps:merge(#{status => RespStatus, headers => RespHeaders}, Acc);
                true ->
                    Acc
            end,
            receive_chunked_response0(Mdhc, ReqId, Timeout, Acc2, ServiceEvents, Verbose);
        {gun_data, _ConnPid, ReqId, nofin, Data} ->
            AccData = maps:get(text, Acc, <<>>),
            RespBody = <<AccData/binary, Data/binary>>,
            Acc1 = maps:put(text, RespBody, Acc),
            Acc2 = decoded_chunked_response(Mdhc, Acc1, Verbose),
            receive_chunked_response0(Mdhc, ReqId, Timeout, Acc2, ServiceEvents, Verbose);
        {gun_data, _ConnPid, ReqId, fin, Data} ->
            AccData = maps:get(text, Acc, <<>>),
            RespBody = <<AccData/binary, Data/binary>>,
            Acc1 = maps:put(text, RespBody, Acc),
            Acc2 = decoded_chunked_response(Mdhc, Acc1, Verbose),
            lists:reverse(maps:get(result, Acc2, []));
        {gun_error, _ConnPid, ReqId, Reason} ->
            lists:reverse([{error, Reason} | maps:get(result, Acc, [])]);
        {gun_error, _ConnPid, Reason} ->
            lists:reverse([{error, Reason} | maps:get(result, Acc, [])]);
        {'DOWN', _MRef, process, _, Reason} ->
            lists:reverse([{error, Reason} | maps:get(result, Acc, [])]);

        {hackney_response, ReqId0, _} when ReqId /= undefined, ReqId /= ReqId0 ->
            receive_chunked_response0(Mdhc, ReqId, Timeout, Acc, ServiceEvents, Verbose);

        {Tag, ReqId0, _, _} when ReqId /= undefined andalso ReqId /= ReqId0 andalso
                                 (Tag == ibrowse_async_headers orelse Tag == ibrowse_async_response orelse
                                  Tag == ibrowse_async_response_end) ->
            receive_chunked_response0(Mdhc, ReqId, Timeout, Acc, ServiceEvents, Verbose);

        {hackney_response, _, {status, StatusInt, _Reason}} ->
            Acc2 = if
                ServiceEvents ->
                    maps:put(status, StatusInt, Acc);
                true ->
                    Acc
            end,
            receive_chunked_response0(Mdhc, ReqId, Timeout, Acc2, ServiceEvents, Verbose);
        {hackney_response, _, {headers, RespHeaders}} ->
            Acc2 = if
                ServiceEvents ->
                    maps:put(headers, RespHeaders, Acc);
                true ->
                    Acc
            end,
            receive_chunked_response0(Mdhc, ReqId, Timeout, Acc2, ServiceEvents, Verbose);
        {hackney_response, _, done} ->
            lists:reverse(maps:get(result, Acc, []));
        {hackney_response, _, Data} ->
            AccData = maps:get(text, Acc, <<>>),
            RespBody = <<AccData/binary, Data/binary>>,
            Acc1 = maps:put(text, RespBody, Acc),
            Acc2 = decoded_chunked_response(Mdhc, Acc1, Verbose),
            receive_chunked_response0(Mdhc, ReqId, Timeout, Acc2, ServiceEvents, Verbose);

        {ibrowse_async_headers, _, HttpCode, RespHeaders} ->
            Acc2 = if
                ServiceEvents ->
                    maps:merge(#{status => list_to_integer(HttpCode),
                                 headers => RespHeaders}, Acc);
                true ->
                    Acc
            end,
            receive_chunked_response0(Mdhc, ReqId, Timeout, Acc2, ServiceEvents, Verbose);
        {ibrowse_async_response, _, Data} ->
            AccData = maps:get(text, Acc, <<>>),
            RespBody = <<AccData/binary, Data/binary>>,
            Acc1 = maps:put(text, RespBody, Acc),
            Acc2 = decoded_chunked_response(Mdhc, Acc1, Verbose),
            receive_chunked_response0(Mdhc, ReqId, Timeout, Acc2, ServiceEvents, Verbose);
        {ibrowse_async_response_end, _} ->
            lists:reverse(maps:get(result, Acc, []));

        {ReqId0, ok} when ReqId /= undefined andalso ReqId /= ReqId0 ->
            receive_chunked_response0(Mdhc, ReqId, Timeout, Acc, ServiceEvents, Verbose);
        {_, ok} -> % stop_async
            lists:reverse(maps:get(result, Acc, []));

        Other when Verbose ->
            log("unexpected message: ~p", [Other]),
            lists:reverse(maps:get(result, Acc, []));
        _ ->
            lists:reverse(maps:get(result, Acc, []))
    after
        Timeout ->
            lists:reverse([timeout | maps:get(result, Acc, [])])
    end.

%% @doc Decodes chunked response.
%% @spec decoded_chunked_response(Client :: mdhc(), Acc :: map(), Verbose :: boolean()) -> [term()]
decoded_chunked_response(Mdhc, Acc, Verbose) ->
    decoded_chunked_response0(get_response_format(Mdhc), Acc, Verbose).

decoded_chunked_response0(Format, Acc, Verbose) ->
    B = maps:get(text, Acc, <<>>),
    {RespBody, Rest} = case binary:split(B, <<10>>) of
        [RespBody0, Rest0] ->
            {read_body_ltrim(RespBody0), read_body_ltrim(Rest0)};
        [RespBody0] ->
            {read_body_ltrim(RespBody0), <<>>}
    end,
    Acc1 = case RespBody of
        <<>> ->
            Acc;
        _ ->
            Result = maps:get(result, Acc, []),
            Resp = maps:put(text, RespBody, Acc),
            Result1 = case parse_response(Resp, Format, Verbose) of
                L when is_list(L) ->
                    lists:foldl(fun (V, AccL) ->
                        [V | AccL]
                    end, Result, L);
                V ->
                    [V | Result]
            end,
            maps:put(result, Result1, Acc)
    end,
    Acc2 = maps:put(text, Rest, Acc1),
    case Rest of
        <<>> ->
            Acc2;
        _ ->
            decoded_chunked_response0(Format, Acc2, Verbose)
    end.

%%-------------------------------------------------------------------
%% internal functions

send_data_genparams(SensorData) ->
    lists:map(fun
        ({Timestamp, Data = [{_, _} | _]}) when is_integer(Timestamp) ->
            [{ns, Timestamp} | Data];
        (Data) ->
             Data
    end, SensorData).

call_method(Mdhc, MdMethod, Args, D) ->
    call_method(Mdhc, MdMethod, Args, D, []).

call_method(Mdhc = #mdhc{ws = WsConnPid}, _, Args, D, _) when is_pid(WsConnPid), is_map(D) ->
    Async = proplists:get_value(async, Args, undefined),
    Opts = maps:get(opts, D, []),
    Opts1 = case proplists:get_value(async, Opts, undefined) of
        undefined ->
            if
                is_boolean(Async) ->
                    [{async, Async} | Opts];
                true ->
                    Opts
            end;
        _ ->
            Opts
    end,
    Frame = maps:put(opts, Opts1, D),
    ws_send(Mdhc, jsx:encode(Frame));

call_method(Mdhc = #mdhc{ws = WsConnPid}, _, _Args, D, _) when is_pid(WsConnPid), is_binary(D) ->
    ws_send(Mdhc, D);

call_method(#mdhc{ws = WsConnPid}, _, _Args, _D, _) when is_pid(WsConnPid) ->
    {error, badarg, <<"chunked transfer encoding is not available">>};

call_method(Mdhc, MdMethod, Args, D, Opts) when is_map(D) ->
    call_method(Mdhc, MdMethod, Args, jsx:encode(D), Opts);

call_method(Mdhc, MdMethod, Args, D, Opts) ->
    Resp0 = call_method_impl(Mdhc, MdMethod, Args, D, Opts),
    %% If is_keycloak_auth_error(Mdhc, Resp0) returns true,
    %% Mdhc is to be modified outside of this call
    %% like in Mdhc2 = keycloak_reload_access_token(Mdhc)
    Resp0.

call_method_impl(Mdhc, MdMethod, Args, D, Opts) ->
    Verbose = is_trace(Mdhc),
    Resp = request(Mdhc, MdMethod, Args, [], D, Opts),
    case Verbose of
        true ->
            log("call_method() response: ~p", [Resp]);
        _ ->
            ok
    end,
    format_response(Resp, get_response_format(Mdhc), Verbose).

%%-------------------------------------------------------------------

ql_query(Mdhc = #mdhc{ws = WsConnPid}, Args, QlText) when is_pid(WsConnPid), is_list(QlText) ->
    ql_query(Mdhc, Args, list_to_binary(QlText));

ql_query(Mdhc = #mdhc{ws = WsConnPid}, Args, QlText) when is_pid(WsConnPid), is_binary(QlText) ->
    Mode = proplists:get_value(mode, Args, <<>>),
    Async = proplists:get_value(async, Args, undefined),
    Stream = proplists:get_value(stream, Args, 0),
    Ver = case proplists:get_value(ver, Args, 2) of
        1 ->
            1;
        _ ->
            2
    end,
    Opts = if
        is_boolean(Async) ->
            [{async, Async}];
        true ->
            []
    end,
    MaybeAsync = case Async of
        true ->
            [{<<"async">>, 1}];
        false ->
            [{<<"async">>, 0}];
        _ ->
            []
    end,
    Frame = #{
        method => <<"q">>,
        context => Mode,
        key => Mdhc#mdhc.app_key,
        opts => Opts,
        params => [{<<"q">>, QlText}, {<<"stream">>, Stream}, {<<"v">>, Ver} | MaybeAsync]
    },
    ws_send(Mdhc, Frame);

ql_query(Mdhc, Args, QlText) ->
    Resp0 = ql_query_impl(Mdhc, Args, QlText),
    %% Mdhc is to be modified outside
    Resp0.

ql_query_impl(Mdhc, Args, QlText) ->
    Verbose = is_trace(Mdhc),
    Stream = proplists:get_value(stream, Args, 0),
    Async = proplists:get_value(async, Args, undefined),
    D0 = iolist_to_binary(io_lib:format("q=~s&key=~s&adm=~s&stream=~p",
            [http_uri_encode(QlText),
             http_uri_encode(binary_to_list(Mdhc#mdhc.app_key)),
             http_uri_encode(binary_to_list(Mdhc#mdhc.admin_key)),
             Stream])),
    D = case Async of
        true ->
            <<D0/binary, "&async=1">>;
        _ ->
            D0
    end,
    Resp = request(Mdhc, ?QL_METHOD_NAME, Args, [], D),
    format_response(Resp, get_response_format(Mdhc), Verbose).


kml_query(Mdhc = #mdhc{ws = WsConnPid}, Args, Content, Opts0) when is_pid(WsConnPid) ->
    Async = proplists:get_value(async, Args, undefined),
    Opts = if
        is_boolean(Async) ->
            [{async, Async} | Opts0];
        true ->
            Opts0
    end,
    Frame = #{
        method => <<"kml">>,
        context => <<"events">>,
        key => Mdhc#mdhc.app_key,
        opts => Opts,
        params => [{<<"q">>, case proplists:get_value(base64, Opts) of
            true ->
                base64:encode(Content);
            _ ->
                Content
        end}]
    },
    ws_send(Mdhc, Frame);

kml_query(Mdhc, Args, Content0, Opts) ->
    Resp0 = kml_query_impl(Mdhc, Args, Content0, Opts),
    %% Mdhc is to be modified outside
    Resp0.

kml_query_impl(Mdhc, Args, Content0, Opts) ->
    Verbose = is_trace(Mdhc),
    UploadOpts = lists:foldr(fun
        ({K, V}, Acc) when is_atom(K) ->
            [lists:concat([http_uri_encode(atom_to_list(K)), '=', http_uri_encode1(V), '&']) | Acc];
        ({K, V}, Acc) when is_list(K) ->
            [lists:concat([http_uri_encode(K), '=', http_uri_encode1(V), '&']) | Acc]
    end, [], Opts),
    Content = case proplists:get_value(base64, Opts) of
        true ->
            base64:encode(Content0);
        _ ->
            Content0
    end,
    D = iolist_to_binary(io_lib:format("~sq=~s&key=~s",
            [lists:append(UploadOpts),
             http_uri_encode(binary_to_list(Content)),
             http_uri_encode(binary_to_list(Mdhc#mdhc.app_key))])),
    Resp = request(Mdhc, ?QL_METHOD_NAME, Args, [], D),
    format_response(Resp, get_response_format(Mdhc), Verbose).


delayed_query(Mdhc, Args, Uuid) when is_integer(Uuid) ->
    delayed_query(Mdhc, Args, integer_to_binary(Uuid));

delayed_query(Mdhc = #mdhc{ws = WsConnPid}, Args, Uuid) when is_pid(WsConnPid), is_binary(Uuid) ->
    Mode = case proplists:get_value(mode, Args) of
        streaming_results ->
            <<"streaming">>;
        events_results ->
            <<"events">>;
        _ ->
            <<>>
    end,
    Async = proplists:get_value(async, Args, undefined),
    Opts = if 
        is_boolean(Async) ->
            [{async, Async}];
        true ->
            []
    end,
    Key = app_or_admin_key(Mdhc),
    Frame = #{
        method => <<"getResults">>,
        context => Mode,
        key => Key,
        opts => Opts,
        params => [{<<"uuid">>, Uuid}]
    },
    ws_send(Mdhc, Frame);

delayed_query(Mdhc, Args, Uuid) when is_binary(Uuid) ->
    Resp0 = delayed_query_impl(Mdhc, Args, Uuid),
    %% Mdhc is to be modified outside
    Resp0.

delayed_query_impl(Mdhc, Args, Uuid) when is_binary(Uuid) ->
    Verbose = is_trace(Mdhc),
    Key = app_or_admin_key(Mdhc),
    D = iolist_to_binary(io_lib:format("uuid=~s&key=~s",
            [http_uri_encode(binary_to_list(Uuid)),
             http_uri_encode(binary_to_list(Key))])),
    Resp = request(Mdhc, ?QL_METHOD_NAME, Args, [], D),
    format_response(Resp, get_response_format(Mdhc), Verbose).

%%-------------------------------------------------------------------

is_keycloak_auth_error(_Mdhc = #mdhc{auth_url = AuthUrl, auth_client_id = ClientId, auth_client_secret = ClientSecret}, _Response)
        when AuthUrl == <<>>; ClientId == <<>>; ClientSecret == <<>> ->
    false;
is_keycloak_auth_error(_Mdhc, {ok, #{<<"error">> := #{<<"code">> := 1001, <<"message">> := <<"authorization error">>}}}) ->
    true;
is_keycloak_auth_error(_Mdhc, _) ->
    false.

%%-------------------------------------------------------------------

get_stream_errors(ParsedStream) ->
    [Result || {Status, Result} <- ParsedStream, Status == error].

merge_stream_values(ParsedStream) ->
    merge_stream_values(ParsedStream, true).

merge_stream_values(ParsedStream, Merge) ->
    ParsedStream1 = lists:filter(fun (Rec) ->
        (not is_map(Rec)) orelse maps:get(a, Rec, undefined) /= undefined
    end, ParsedStream),
    merge_stream_values_helper(ParsedStream1, Merge).

merge_stream_values_helper([], _Merge) ->
    #{};

merge_stream_values_helper(ParsedStream, _Merge) when length(ParsedStream) == 1 ->
    Rec = hd(ParsedStream),
    if
        is_map(Rec) ->
            Data = maps:get(<<"data">>, Rec),
            maps:get(<<"values">>, hd(Data));
        true ->
            Rec
    end;

merge_stream_values_helper(ParsedStream, false) ->
    {ok, Recs} = jsonseq_to_json(ParsedStream),
    [maps:get(<<"values">>, hd(maps:get(<<"data">>, Rec))) || Rec <- Recs];

merge_stream_values_helper(ParsedStream, true) ->
    {ok, Recs} = jsonseq_to_json(ParsedStream),
    R = [maps:get(<<"values">>, hd(maps:get(<<"data">>, Rec))) || Rec <- Recs],
    lists:foldl(fun (D, Acc) ->
        maps:fold(fun (Alias, Value, Values) ->
            case maps:get(Alias, Values, undefined) of
                undefined when is_list(Value) ->
                    maps:put(Alias, Value, Values);
                undefined ->
                    throw(<<"Unexpected query response format">>);
                V when is_map(Value) ->
                    maps:put(Alias, maps:merge(V, Value), Values);
                V when is_list(Value) ->
                    maps:put(Alias, [Value | V], Values);
                _ ->
                    throw(<<"Unexpected query response format">>)
            end
        end, Acc, D)
    end, hd(R), tl(R)).


jsonseq_to_json(ParsedStream) ->
    {Recs, Errors, Postpone} = lists:foldl(fun
        ({postpone, Rec}, {AccR, AccE, AccP}) ->
            {AccR, AccE, [Rec | AccP]};
        ({error, Rec}, {AccR, AccE, AccP}) ->
            {AccR, [Rec | AccE], AccP};
        (Rec, {AccR, AccE, AccP}) ->
            {[Rec | AccR], AccE, AccP}
    end, {[], [], []}, ParsedStream),
    case {Recs, Errors, Postpone} of
        _ when length(Postpone) > 0 ->
            {postpone, lists:reverse(Postpone)};
        _ when length(Errors) > 0 ->
            {error, lists:reverse(Errors)};
        _ ->
            {ok, lists:reverse(Recs)}
    end.

maybe_parse_json(#{headers := Headers} = Resp, Format, Verbose) when is_list(Headers) ->
    maybe_parse_json(maps:put(headers, maps:from_list(Headers), Resp), Format, Verbose);

maybe_parse_json(#{headers := Headers, text := Text}, Format, Verbose) ->
    IsSeq = maps:get(<<"content-type">>, Headers, undefined) == <<"application/json-seq">>,
    try
        JsxOpt = case Format of
            lists ->
                [];
            _ ->
                [return_maps]
        end,
        if
            IsSeq ->
                Lines0 = binary:split(Text, <<16#1e>>, [global, trim_all]),
                Lines = [read_body_ltrim(Line) || Line <- Lines0],
                [parse_result(jsx:decode(Line, JsxOpt), size(Line), Format, Verbose) || Line <- Lines];
            true ->
                parse_result(jsx:decode(Text, JsxOpt), size(Text), Format, Verbose)
        end
    catch
        error:badarg ->
            if
                IsSeq ->
                    [Text];
                true ->
                    Text
            end
    end.


parse_response(#{status := Code}, _Format, _Verbose) when Code /= 200 ->
    {error, Code};

parse_response(#{status := _, headers := _, text := _} = Resp, Format, Verbose) ->
    maybe_parse_json(Resp, Format, Verbose);

parse_response(Resp, Format, Verbose) when is_map(Resp) ->
    parse_result(Resp, undefined, Format, Verbose);

parse_response(Resp, Format, Verbose) when is_list(Resp) ->
    parse_result(Resp, undefined, Format, Verbose);

parse_response(_Text, _Format, _Verbose) ->
    {error, <<"unexpected response">>}.

parse_result([{<<"result">>, [{<<"uuid">>, Uuid}]}], _RTextLen, lists, _Verbose) ->
    {postpone, Uuid};

parse_result([{<<"result">>, Result}], RTextLen, lists, _Verbose) ->
    case proplists:lookup(<<"data">>, Result) of
        {_, [V0 | VT] = Data} ->
            Data1 = case proplists:lookup(<<"ms">>, V0) of
                {_, _} -> [[{<<"ms">>, RTextLen} | proplists:delete(<<"ms">>, V0)] | VT]; _ -> Data
            end,
            [{<<"data">>, Data1} | proplists:delete(<<"data">>, Result)];
        _ ->
           Result
    end;

parse_result(#{<<"result">> := #{<<"uuid">> := Uuid}}, _RTextLen, _Format, _Verbose) ->
    {postpone, Uuid};

parse_result(#{<<"result">> := #{<<"data">> := [#{<<"ms">> := _} = V0 | VT]} = Result}, RTextLen, _Format, _Verbose) when RTextLen > 0 ->
    maps:put(<<"data">>, [maps:put(<<"_qsz">>, RTextLen, V0) | VT], Result); % in python {ok, ..}

parse_result(#{<<"result">> := Result}, _RTextLen, _Format, _Verbose) ->
    Result; % in python {ok, ..}

parse_result([{<<"error">>, Props}], _RTextLen, lists, _Verbose) ->
    case proplists:lookup(<<"message">>, Props) of
        {_, <<"the job is postponed">>} ->
            {_, Details} = proplists:lookup(<<"details">>, Props),
            {_, Uuid} = proplists:lookup(<<"uuid">>, Details),
            {postpone, Uuid};
        {_, Message} ->
            {error, Message};
        none ->
            {error, Props}
    end;

parse_result(#{<<"error">> := #{
                    <<"message">> := <<"the job is postponed">>,
                    <<"details">> := #{<<"uuid">> := Uuid}}}, _RTextLen, _Format, _Verbose) ->
    {postpone, Uuid};

parse_result(#{<<"error">> := #{<<"message">> := Message}}, _RTextLen, _Format, _Verbose) ->
    {error, Message};

parse_result(#{<<"error">> := Error}, _RTextLen, _Format, _Verbose) ->
    {error, Error};

parse_result(_RText, _RTextLen, _Format, _Verbose) ->
    {error, <<"protocol">>}.

%%-------------------------------------------------------------------

app_or_admin_key(#mdhc{app_key = <<>>, admin_key = Key}) ->
    Key;

app_or_admin_key(#mdhc{app_key = Key}) ->
    Key.

%%-------------------------------------------------------------------

format_response(Resp, Format, Verbose) ->
    format_response0(Resp, Format, Verbose).

format_response0({ok, _Status, _Headers, Body}, raw, _Verbose) ->
    try
        {ok, jsx:decode(Body, [return_maps])}
    catch
        error:badarg ->
            {error, Body}
    end;

format_response0(Error = {error, _}, _, _) ->
    Error;

format_response0(Resp, raw, _Verbose) when is_map(Resp) ->
    {ok, Resp};

format_response0(I = {ibrowse_req_id, _}, _, _) ->
    I;

format_response0(I = {hackney_req_id, _}, _, _) ->
    I;

format_response0(I = {gun_req_id, _}, _, _) ->
    I;

format_response0({ok, HttpCode, Headers, Body}, Format, Verbose) when is_list(HttpCode) ->
    parse_response(#{status => list_to_integer(HttpCode), headers => Headers, text => Body}, Format, Verbose);

format_response0({ok, Status, Headers, Body}, Format, Verbose) ->
    parse_response(#{status => Status, headers => Headers, text => Body}, Format, Verbose).

%%-------------------------------------------------------------------

log(Fmt, Args, true) ->
    log(Fmt, Args);

log(_, _, _) ->
    ok.

log(Fmt, Args) ->
    error_logger:info_msg(Fmt, Args).

method_info(Mdhc, setData, Opts) ->
    Endpoint = case proplists:get_value(mode, Opts) of
        geo_events ->
            ?EP_INGEST2 ++ http_uri_encode(binary_to_list(Mdhc#mdhc.app_key));
        _ ->
            ?EP_INGEST
    end,
    {post, Endpoint, <<"application/json">>, case Mdhc#mdhc.app_key of
        <<>> ->
            Mdhc#mdhc.admin_key;
        _ ->
            Mdhc#mdhc.app_key
    end};
method_info(Mdhc, ping, _) ->
    {post, ?EP_INGEST, <<"application/json">>, Mdhc#mdhc.app_key};
method_info(Mdhc, newApiKey, _) ->
    {post, ?EP_ADMIN, <<"application/json">>, Mdhc#mdhc.admin_key};
method_info(Mdhc, assureApiKey, _) ->
    {post, ?EP_ADMIN, <<"application/json">>, Mdhc#mdhc.admin_key};
method_info(Mdhc, deleteApiKey, _) ->
    {post, ?EP_ADMIN, <<"application/json">>, Mdhc#mdhc.admin_key};
method_info(Mdhc, newAdminKey, _) ->
    {post, ?EP_ADMIN, <<"application/json">>, Mdhc#mdhc.admin_key};
method_info(Mdhc, assureAdminKey, _) ->
    {post, ?EP_ADMIN, <<"application/json">>, Mdhc#mdhc.admin_key};
method_info(Mdhc, deleteAdminKey, _) ->
    {post, ?EP_ADMIN, <<"application/json">>, Mdhc#mdhc.admin_key};
method_info(Mdhc, ?QL_METHOD_NAME, Opts) ->
    Mode = proplists:get_value(mode, Opts),
    Ver = proplists:get_value(ver, Opts),
    Url = case Mode of
        events when Ver =:= 2 ->
            ?EP_QL ++ "?v=2";
        events ->
            ?EP_QL;
        kml ->
            ?EP_KML;
        events_results ->
            ?EP_RESULT2;
        results ->
            ?EP_RESULT
    end,
    {post, Url, <<"application/x-www-form-urlencoded">>, case Mdhc#mdhc.app_key of
        <<>> ->
            Mdhc#mdhc.admin_key;
        _ ->
            Mdhc#mdhc.app_key
    end}.

get_ssl_options(Options) ->
    case proplists:get_value(is_ssl, Options) of
        true ->
            [{is_ssl, true}] ++ case proplists:get_value(ssl_options, Options, []) of
                X when is_list(X) ->
                    [{ssl_options, X}];
                _ ->
                    [{ssl_options, []}]
            end;
        _ ->
            []
    end.

request(Mdhc, MdMethod, Args, Headers0, Content) ->
    request(Mdhc, MdMethod, Args, Headers0, Content, []).

request(Mdhc, MdMethod, Args, Headers0, Content, Opts) ->
    request0(Mdhc, MdMethod, Args, Headers0, Content, Opts).

request0(Mdhc = #mdhc{ip = Ip, port = Port, options = MdhcOpts}, MdMethod, Args, HeadersL, Content, Opts) ->
    Scheme = case proplists:get_value(use_https, MdhcOpts, false) of
        true ->
            "https://";
        _ ->
            "http://"
    end,
    {HttpMethod, Uri0, ContentType0, SignKey} = method_info(Mdhc, MdMethod, Args),
    HttpVerbose = case proplists:get_value(verbose, Args) of
        true ->
            "?verbose=true";
        false ->
            "?verbose=false";
        _ ->
            ""
    end,
    %% compress
    {Body0, Headers0} = if
        is_binary(Content) orelse (is_tuple(Content) andalso is_function(element(1, Content), 1)) ->
            {Content, HeadersL};
        true ->
            request_prepare_content(Uri0 == ?EP_INGEST, Content, Opts)
    end,
    ContentType = proplists:get_value(<<"Content-Type">>, Headers0, ContentType0),
    %%
    Uri = Uri0 ++ HttpVerbose,
    Url = lists:concat([Scheme, Ip, ":", Port, "/", Uri]),
    BUri = list_to_binary(Uri),
    {{Signature0, AuthHeader}, IsChunked} = case Body0 of
        {Generator0, _} when is_function(Generator0, 1) ->
            {make_auth_header(Mdhc, SignKey, MdMethod, BUri, undefined, ContentType, ?DEFAULT_AUTH_VERSION, <<?MDTSDB_AUTH2_STREAMING>>),
             true};
         _ ->
            {make_auth_header(Mdhc, SignKey, MdMethod, BUri, sha256_hexdigest(Body0), ContentType), false}
    end,
    Headers = request_merge_headers([
        {<<"Content-Type">>, ContentType},
        {<<"Authorization">>, AuthHeader}], Headers0),
    SSLOptions = get_ssl_options(Mdhc#mdhc.options),
    Body = case Body0 of
        {Generator, GeneratorState} when is_function(Generator, 1) ->
            MdMethodBin = (atom_to_binary(MdMethod, utf8)),
            {fun ({Sg, S}) ->
                case Generator(S) of
                    {ok, GenData, NewS} ->
                        Timeslice = auth_timeslice(),
                        Pg = sha256_hexdigest(<<Sg/binary, 32, GenData/binary>>),
                        NewSg = auth_signature(Timeslice, BUri, MdMethodBin, Pg, ContentType, SignKey, Mdhc),
                        {ok, <<NewSg/binary, 32, GenData/binary, 30>>, {NewSg, NewS}};
                    Other ->
                        Other
                end
            end, {Signature0, GeneratorState}};
        _ ->
            Body0
    end,
    IsAsyncResponse = is_async_response(Mdhc, IsChunked),
    case proplists:get_value(httpc, Mdhc#mdhc.options, hackney) of
        ibrowse ->
            Options = if
                IsChunked, IsAsyncResponse ->
                    [{transfer_encoding, chunked},
                     {stream_full_chunks, true},
                     {stream_to, self()}];
                IsChunked ->
                    [{transfer_encoding, chunked}];
                IsAsyncResponse ->
                    [{stream_full_chunks, true},
                     {stream_to, self()}];
                true ->
                    []
            end ++ [{response_format, binary}] ++ SSLOptions,
            case get_opts_timeout(Args, Mdhc) of
                Timeout when is_integer(Timeout); Timeout =:= 'infinity' ->
                    ibrowse:send_req(Url, Headers, HttpMethod, Body, Options, Timeout);
                _ ->
                    ibrowse:send_req(Url, Headers, HttpMethod, Body, Options)
            end;
        hackney ->
            Pool = proplists:get_value(pool, Mdhc#mdhc.options, default),
            Options0 = SSLOptions ++ [{pool, Pool} | case get_opts_timeout(Args, Mdhc) of
                Timeout when is_integer(Timeout); Timeout =:= infinity ->
                    [{connect_timeout, Timeout}];
                _ ->
                    []
            end],
            if
                IsAsyncResponse ->
                    request_async_hackney(HttpMethod, Url, Headers, Body, [async | Options0], 1);
                true ->
                    hackney:request(HttpMethod, Url, Headers, Body, [with_body | Options0])
            end;
        gun ->
            Options0 = SSLOptions ++ case get_opts_timeout(Args, Mdhc) of
                Timeout when is_integer(Timeout); Timeout =:= infinity ->
                    [{connect_timeout, Timeout}];
                _ ->
                    []
            end,
            if
                IsAsyncResponse ->
                    gun_request_async(HttpMethod, Url, Headers, Body, Options0);
                true ->
                    gun_request(HttpMethod, Url, Headers, Body, Options0)
            end;
        _ ->
            {error, general, unknown_http_client}
    end.

request_async_hackney(HttpMethod, Url, Headers, Body, Options, Retry) ->
    case hackney:request(HttpMethod, Url, Headers, Body, Options) of
        {ok, HackneyCliRef} ->
            {hackney_req_id, HackneyCliRef};
        {error, closed} when Retry > 0 ->
            request_async_hackney(HttpMethod, Url, Headers, Body, Options, Retry - 1);
        AsyncError ->
            AsyncError
    end.

%%-------------------------------------------------------------------

request_prepare_content(false, Content, _Opts) ->
    {jsx:encode(Content), []};
request_prepare_content(true, Content, Opts0) ->
    Opts = if is_map(Opts0) -> Opts0; true -> maps:from_list(Opts0) end,
    CompressionLevel = max(0, min(9, case Opts of
        #{compression_level := Level} ->
            Level;
        #{"compression_level" := Level} ->
            Level;
        #{<<"compression_level">> := Level} ->
            Level;
        _ ->
            6
    end)),
    case Opts of
        #{compression := gzip} ->
            {compress(jsx:encode(Content), CompressionLevel), [{<<"Content-Encoding">>, <<"gzip">>}]};
        #{"compression" := "gzip"} ->
            {compress(jsx:encode(Content), CompressionLevel), [{<<"Content-Encoding">>, <<"gzip">>}]};
        #{<<"compression">> := <<"gzip">>} ->
            {compress(jsx:encode(Content), CompressionLevel), [{<<"Content-Encoding">>, <<"gzip">>}]};
        #{compression := bson} ->
            {mdhcemongo_bson:encode(maps:to_list(maps_atom_to_binary(Content))),
             [{<<"Content-Encoding">>, <<"bson">>}, {<<"Content-Type">>, <<"application/octet-stream">>}]};
        #{"compression" := "bson"} ->
            {mdhcemongo_bson:encode(maps:to_list(maps_atom_to_binary(Content))),
             [{<<"Content-Encoding">>, <<"bson">>}, {<<"Content-Type">>, <<"application/octet-stream">>}]};
        #{<<"compression">> := <<"bson">>} ->
            {mdhcemongo_bson:encode(maps:to_list(maps_atom_to_binary(Content))),
             [{<<"Content-Encoding">>, <<"bson">>}, {<<"Content-Type">>, <<"application/octet-stream">>}]};
        #{compression := 'gzip-bson'} ->
            {compress(mdhcemongo_bson:encode(maps:to_list(maps_atom_to_binary(Content))), CompressionLevel),
             [{<<"Content-Encoding">>, <<"gzip-bson">>}, {<<"Content-Type">>, <<"application/octet-stream">>}]};
        #{"compression" := "gzip-bson"} ->
            {compress(mdhcemongo_bson:encode(maps:to_list(maps_atom_to_binary(Content))), CompressionLevel),
             [{<<"Content-Encoding">>, <<"gzip-bson">>}, {<<"Content-Type">>, <<"application/octet-stream">>}]};
        #{<<"compression">> := <<"gzip-bson">>} ->
            {compress(mdhcemongo_bson:encode(maps:to_list(maps_atom_to_binary(Content))), CompressionLevel),
             [{<<"Content-Encoding">>, <<"gzip-bson">>}, {<<"Content-Type">>, <<"application/octet-stream">>}]};
        _ ->
            {jsx:encode(Content), []}
    end.

maps_atom_to_binary(Map) when is_map(Map) ->
    maps:fold(fun (Key, Value, Acc) ->
        Key1 = case Key of
            _ when is_atom(Key) ->
                atom_to_binary(Key, latin1);
            _ when is_integer(Key) ->
                integer_to_binary(Key);
            _ when is_list(Key) ->
                list_to_binary(Key)
        end,
        Value1 = case Value of
            _ when is_atom(Value) ->
                atom_to_binary(Value, latin1);
            _ ->
                maps_atom_to_binary(Value)
        end,
        maps:put(Key1, Value1, Acc)
    end, #{}, Map);
maps_atom_to_binary(List) when is_list(List) ->
    [maps_atom_to_binary(Value) || Value <- List];
maps_atom_to_binary({Key, Value}) when is_integer(Key) ->
    {integer_to_binary(Key), maps_atom_to_binary(Value)};
maps_atom_to_binary({Key, Value}) when is_atom(Key) ->
    {atom_to_binary(Key, latin1), maps_atom_to_binary(Value)};
maps_atom_to_binary({Key, Value}) when is_list(Key) ->
    {list_to_binary(Key), maps_atom_to_binary(Value)};
maps_atom_to_binary(Value) ->
    Value.

request_merge_headers(Headers0, []) ->
    Headers0;
request_merge_headers(Headers0, Headers1) ->
    maps:to_list(maps:merge(maps:from_list(Headers0), maps:from_list(Headers1))).

%%------------------------------------------------------------------------------

compress(Data, CompressionLevel) ->
    Z = zlib:open(),
    Bs = try
             zlib:deflateInit(Z, CompressionLevel),
             B = zlib:deflate(Z, Data, finish),
             zlib:deflateEnd(Z),
             B
         after
             zlib:close(Z)
         end,
    iolist_to_binary(Bs).

%%------------------------------------------------------------------------------

get_binary_option(Opts, Key, Default) ->
    case proplists:get_value(Key, Opts) of
        Bin when is_binary(Bin) ->
            Bin;
        _ ->
            Default
    end.

is_trace(#mdhc{options = Opts}) ->
    proplists:get_bool(trace, Opts).

is_profile(#mdhc{options = Opts}) ->
    proplists:get_bool(profile, Opts).

is_async_response(#mdhc{options = Opts}, IsChunked) ->
    case proplists:get_value(async_response, Opts) of
        B when is_boolean(B) ->
            B;
        _ ->
            IsChunked
    end.

get_response_format(#mdhc{options = Opts}) ->
    proplists:get_value(response, Opts, undefined).

set_response_format(Mdhc = #mdhc{options = Opts0}, Fmt) ->
    Mdhc#mdhc{options = [{response, Fmt} | Opts0]}.

get_opts_timeout(Args, #mdhc{options = Opts}) ->
    case proplists:get_value(timeout, Args) of
        undefined ->
            proplists:get_value(timeout, Opts);
        R ->
            R
    end.

get_opts_admin_key(Opts) ->
    get_binary_option(Opts, admin_key, <<>>).

get_opts_app_key(Opts) ->
    get_binary_option(Opts, app_key, <<>>).

get_opts_secret_key(Opts) ->
    get_binary_option(Opts, secret_key, <<>>).

http_uri_encode1(V) when is_list(V) ->
    http_uri_encode1(V);

http_uri_encode1(V) when is_binary(V) ->
    http_uri_encode1(binary_to_list(V));

http_uri_encode1(V) when is_atom(V) ->
    http_uri_encode1(atom_to_list(V));

http_uri_encode1(V) ->
    V.

maybe_prepend(_, <<>>) ->
    <<>>;

maybe_prepend(C, B) ->
    <<C, B/binary>>.

read_body_ltrim(<<I, B/binary>>) when I =:= 10; I =:= 13 ->
    read_body_ltrim(B);

read_body_ltrim(B) ->
    B.

%%------------------------------------------------------------------------------

http_uri_encode(A) ->
    Q = tl(uri_string:compose_query([{"", A}])),
    if
        is_binary(A) ->
            list_to_binary(Q);
        true ->
            Q
    end.

sha256_hexdigest(B) ->
    binary_to_hex(crypto:hash(sha256, B)).

bits_to_hex(I) when I < 10 ->
    I + 48;

bits_to_hex(I) ->
    I + 87.

binary_to_hex(B) ->
    << <<(bits_to_hex(I1)):8, (bits_to_hex(I2)):8>> || <<I1:4, I2:4>> <= B >>.

default_auth_mode(Mdhc) ->
    case proplists:get_value(auth_mode, Mdhc#mdhc.options, ?DEFAULT_AUTH_VERSION) of
        ?BEARER_AUTH_VERSION ->
            ?BEARER_AUTH_VERSION;
        _ ->
            ?DEFAULT_AUTH_VERSION
    end.


auth_prefix(?DEFAULT_AUTH_VERSION, _Mdhc) ->
    <<?MDTSDB_AUTH2>>;
auth_prefix(?BEARER_AUTH_VERSION, Mdhc) ->
    TokenType = case Mdhc#mdhc.access_token_type of
        <<>> ->
            <<?MDTSDB_AUTH_TOKEN_TYPE>>;
        TokenType0 ->
            TokenType0
    end,
    case binary:last(TokenType) of
        32 ->
            TokenType;
        _ ->
            <<TokenType/binary, 32>>
    end.

auth_timeslice() ->
    integer_to_binary(tnow_lite() div 1000).

make_auth_header(Mdhc, SignKey, MdMethod, Uri, PayloadDigest0, ContentType) ->
    make_auth_header(Mdhc, SignKey, MdMethod, Uri, PayloadDigest0, ContentType, default_auth_mode(Mdhc)).

make_auth_header(Mdhc, SignKey, MdMethod, Uri, PayloadDigest0, ContentType, AuthMode) ->
    make_auth_header(Mdhc, SignKey, MdMethod, Uri, PayloadDigest0, ContentType, AuthMode, auth_prefix(AuthMode, Mdhc)).

make_auth_header(Mdhc, SignKey, MdMethod, Uri, PayloadDigest0, ContentType, AuthMode, AuthPrefix) ->
    MdMethodBin = (atom_to_binary(MdMethod, utf8)),
    Timeslice = auth_timeslice(),
    case AuthMode of
        ?BEARER_AUTH_VERSION ->
            PayloadDigest = case PayloadDigest0 of
                undefined ->
                    sha256_hexdigest(<<>>);
                _ ->
                    PayloadDigest0
            end,
            AccessToken = Mdhc#mdhc.access_token,
            Signature = auth_signature(Timeslice, Uri, MdMethodBin, PayloadDigest, ContentType, SignKey, Mdhc),
            {Signature, binary_to_list(<<AuthPrefix/binary, AccessToken/binary>>)};
        ?DEFAULT_AUTH_VERSION ->
            PayloadDigest = case PayloadDigest0 of
                undefined when AuthMode =:= 2 ->
                    sha256_hexdigest(<<>>);
                _ ->
                    PayloadDigest0
            end,
            Signature = auth_signature(Timeslice, Uri, MdMethodBin, PayloadDigest, ContentType, SignKey, Mdhc),
            KeyInfo = if
                SignKey =:= Mdhc#mdhc.app_key ->
                    $s;
                SignKey =:= Mdhc#mdhc.admin_key ->
                    $a;
                true ->
                    $u
            end,
            {Signature,
             binary_to_list(<<AuthPrefix/binary, SignKey/binary, 32, Signature/binary, 32, KeyInfo, $,, MdMethodBin/binary>>)}
    end.

auth_signature(TNow, Uri, MdMethod, PayloadDigest, ContentType, UserKey, Mdhc) ->
    SecretKey1 = crypto:mac(hmac, sha256, Mdhc#mdhc.secret_key, TNow),
    SecretKey2 = crypto:mac(hmac, sha256, SecretKey1, MdMethod),
    Digest1 = sha256_hexdigest(<<$/, Uri/binary, 10, ContentType/binary, 10, PayloadDigest/binary>>),
    Digest2 = <<TNow/binary, 10, UserKey/binary, 10, Digest1/binary>>,
    Digest3 = crypto:mac(hmac, sha256, SecretKey2, Digest2),
    binary_to_hex(Digest3).

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------

gun_request(Method, Url, Headers, Body, Opts) ->
    try
        {Host, Port, Path} = gun_parse_url(Url),
        Options0 = case Opts of
            _ when is_list(Opts) ->
                gun_plist_to_map(Opts);
            _ ->
                Opts
        end,
        Timeout = maps:get(connect_timeout, Options0, 5000),
        Options = maps:remove(connect_timeout, Options0),
        Connection = case gun:open(Host, Port, Options) of
            {ok, Conn} ->
                case gun:await_up(Conn, Timeout) of
                    {ok, _Protocol} ->
                        {ok, Conn};
                    Error1 ->
                        Error1
                end;
            Error ->
                Error
        end,
        case Connection of
            {ok, ConnPid} ->
                MethodBin = gun_method(Method),
                StreamRef = gun:request(ConnPid, MethodBin, Path, Headers, Body),
                case gun:await(ConnPid, StreamRef, Timeout) of
                    {response, fin, RespStatus, RespHeaders} ->
                        {ok, RespStatus, RespHeaders, <<>>};
                    {response, nofin, RespStatus, RespHeaders} ->
                        case gun:await_body(ConnPid, StreamRef, Timeout) of
                            {ok, RespBody} ->
                                {ok, RespStatus, RespHeaders, RespBody};
                            Error2 ->
                                Error2
                        end;
                    Error3 ->
                        Error3
                end;
            Error4 ->
                Error4
        end
    catch
        error:Msg ->
            {error, iolist_to_binary(io_lib:format("~p", [Msg]))}
    end.

%%--------------------------------------------------------------------

gun_request_async(Method, Url, Headers, Body, Opts) ->
    try
        {Host, Port, Path} = gun_parse_url(Url),
        Options0 = case Opts of
            _ when is_list(Opts) ->
                gun_plist_to_map(Opts);
            _ ->
                Opts
        end,
        Timeout = maps:get(connect_timeout, Options0, 5000),
        Options = maps:remove(connect_timeout, Options0),
        Connection = case gun:open(Host, Port, Options) of
            {ok, Conn} ->
                case gun:await_up(Conn, Timeout) of
                    {ok, _Protocol} ->
                        {ok, Conn};
                    Error1 ->
                        Error1
                end;
            Error ->
                Error
        end,
        case Connection of
            {ok, ConnPid} ->
                MethodBin = gun_method(Method),
                StreamRef = gun:request(ConnPid, MethodBin, Path, Headers, Body),
                {gun_req_id, StreamRef};
            Error2 ->
                Error2
        end
    catch
        error:Msg ->
            {error, iolist_to_binary(io_lib:format("~p", [Msg]))}
    end.

%%-------------------------------------------------------------------

-spec gun_parse_url(Url :: list() | binary()) -> {list(), pos_integer(), list()}.
gun_parse_url(Url) when is_binary(Url) ->
    gun_parse_url(binary_to_list(Url));
gun_parse_url(Url) when is_list(Url) ->
    Details = uri_string:parse(Url),
    Host = maps:get(host, Details, ""),
    Port = maps:get(port, Details, 80),
    Path = maps:get(path, Details, ""),
    Query = maps:get(query, Details, ""),
    Fragment = maps:get(fragment, Details, ""),
    PathQuery = case Query of
        [] ->
            Path;
        _ ->
            Path ++ "?" ++ Query
    end,
    PathQueryFragment = case Fragment of
        [] ->
            PathQuery;
        _ ->
            PathQuery ++ "#" ++ Fragment
    end,
    {Host, Port, PathQueryFragment}.


-spec gun_plist_to_map(L :: list()) -> map().
gun_plist_to_map(L) -> 
    maps:from_list(lists:map(fun
        ({K, V}) when is_list(V) ->
            case lists:all(fun(It) -> is_tuple(It) end, V) of
                true -> {K, gun_plist_to_map(V)}; false -> {K, V}
            end;
        (I) ->
            I
    end, L)).

gun_method('get') ->
    <<"GET">>;
gun_method('post') ->
    <<"POST">>;
gun_method('put') ->
    <<"PUT">>;
gun_method('options') ->
    <<"OPTIONS">>;
gun_method('patch') ->
    <<"PATCH">>;
gun_method('delete') ->
    <<"DELETE">>.

%%------------------------------------------------------------------------------

-spec process_access_token(Token :: binary(), Opts :: [term()]) -> [term()].
process_access_token(Token, Opts) ->
    case Token of
        <<>> ->
            Opts;
        _ ->
            [_, B64Token | _] = binary:split(Token, <<$.>>, [global]),
            Token1 = decode_base64(B64Token),
            TokenObj = jsx:decode(Token1, [return_maps]),
            MdtsdbAdminKey = maps:get(<<"clientId">>, TokenObj, <<>>),
            RemoveList = [app_key, secret_key, admin_key, auth_mode],
            Opts1 = lists:foldl(fun (Key, Acc) -> proplists:delete(Key, Acc) end, Opts, RemoveList),
            [{app_key, <<>>}, {secret_key, <<>>}, {admin_key, MdtsdbAdminKey}, {auth_mode, ?BEARER_AUTH_VERSION} | Opts1]
    end.

-spec decode_base64(Base64 :: binary()) -> binary().
decode_base64(Base64) ->
    try
        base64:decode(Base64)
    catch
        error:_ -> %% could be missing =
            try
                base64:decode(<<Base64/binary, $=>>)
            catch
                error:_ -> %% could be missing ==
                    base64:decode(<<Base64/binary, $=, $=>>)
            end

    end.

%%------------------------------------------------------------------------------
%% Deprecated

%% @doc Uploads data from sensors to server.
%%
%%      There are two modes of the method: batch multi-swimlane send and one-swimlane send.
%%      In the one-swimlane send data swimline is determined by the application key of the client.
%%      Several time points can be sent at once, either in a zipped list tuples
%%          ```{Timestamp, SensorData}'''
%%      where Timestamp is a Unix timestamp and SensorData argument has the same format
%%      as in send_streaming_data/2, or in a list of lists, where each item holds both
%%      a timestamp and sensor values, e.g.:
%%          ```[[{ns, 1421507438}, {3, 30}], [{ns, 1421507439}, {1, 10}, {2, 20}]]'''
%%
%%      In the case of batch multi-swimlane send, the application key of the client is used only
%%      for authentication. Destination swimlanes are listed in the method 'params' field.
%%      Sensor data must be formatted as the following:
%%      ```[{'key': 'swimlane1', 'data': ...}, {'key': 'swimlane2', 'data': ...}, ...]'''
%%      where 'data' format is the same as sensor data for one-swimlane send data version of the method.
%%
%%      This method can be called by admin client, so that admin key/secret key are used for authentication.
%%      Only batch multi-swimlane send is available for sending data by the admin client.
%%
%%      Sensor value is either scalar value (numeric or binary string), or the json object encoded
%%      in jsx:encode() format.
%% @spec send_events_data(Client :: mdhc(), SensorData :: list()) ->
%%                              Properties :: list() | {error, Reason :: term()}
send_events_data(Mdhc, SensorData) ->
    send_data(events, Mdhc, SensorData, []).

%% @doc Uploads data from sensors to server.
%%
%%      Data swimline is determined by the application key.
%%      Several sensor values can be sent at once, so that the SensorData argument contains a vector
%%      of pairs sensor identifier/sensor value, e.g.:
%%      ```[{1, 10}, {2, 20}]'''
%%
%%      Sensor value is either scalar value (numeric or binary string), or a list of fields of
%%      the json structure encoded in jsx:encode() format.
%% @spec send_events_data(Client :: mdhc(), UnixTimestamp :: integer(), SensorData :: list()) ->
%%                              Properties :: list() | {error, Reason :: term()}
send_events_data(Mdhc, T0, SensorData) ->
    send_data(events, Mdhc, T0, SensorData, []).

send_events_data(Mdhc, T0, SensorData, ReqOpts) ->
    send_data(events, Mdhc, T0, SensorData, [], ReqOpts).

%% @doc Uploads data from sensors to server.
%%
%%      Data swimline is determined by the application key.
%%      Several sensor values can be sent at once, so that the SensorData argument contains a vector
%%      of pairs sensor identifier/sensor value, e.g.:
%%      ```[ [{ns, Time}, {1, 10}, {2, 20}], ... ]'''
%%
%%      Sensor value is either scalar value (numeric or binary string), or a list of fields of
%%      the json structure encoded in jsx:encode() format.
%% @spec send_events_data(Client :: mdhc(), UnixTimestamp :: integer(), SensorData :: list()) ->
%%                              Properties :: list() | {error, Reason :: term()}
send_events_data_vector(Mdhc, TimeSeries) ->
    send_data_vector(events, Mdhc, TimeSeries, []).

send_events_data_vector(Mdhc, TimeSeries, ReqOpts) ->
    send_data_vector(events, Mdhc, TimeSeries, [], ReqOpts).

%% @doc Uploads data from sensors to server using an 'events' mode.
%%      Uses async mode if websocket connection is set.
%%
%%      Data swimline is determined by the application key.
%%      Several sensor values can be sent at once, so that the SensorData argument contains a vector
%%      of pairs sensor identifier/sensor value, e.g.:
%%      ```[{1, 10}, {2, 20}]'''
%%
%%      Sensor value is either scalar value (numeric or binary string), or a list of fields of
%%      the json structure encoded in jsx:encode() format.
%% @spec async_send_events_data(Client :: mdhc(), UnixTimestamp :: integer(), SensorData :: list()) ->
%%                              Properties :: list() | {error, Reason :: term()}
async_send_events_data(Mdhc, T0, SensorData) ->
    send_data(events, Mdhc, T0, SensorData, [{async, true}]).

async_send_events_data(Mdhc, T0, SensorData, ReqOpts) ->
    send_data(events, Mdhc, T0, SensorData, [{async, true}], ReqOpts).

%% @doc Uploads data from sensors to server.
%%      Uses async mode if websocket connection is set.
%%
%%      Data swimline is determined by the application key.
%%      Several time points can be sent at once, either in a zipped list tuples
%%          ```{Timestamp, SensorData}'''
%%      where Timestamp is a Unix timestamp and SensorData argument has the same format
%%      as in send_streaming_data/2, or in a list of lists, where each item holds both
%%      a timestamp and sensor values, e.g.:
%%          ```[[{ns, 1421507438}, {3, 30}], [{ns, 1421507439}, {1, 10}, {2, 20}]]'''
%%
%%      If timestamp is not set explicitly, server will set the timestamp itself using current server time.
%%
%%      Sensor value is either scalar value (numeric or binary string), or a list of fields of
%%      the json structure encoded in jsx:encode() format.
%% @spec async_send_events_data(Client :: mdhc(), SensorData :: list()) ->
%%                              Properties :: list() | {error, Reason :: term()}
async_send_events_data(Mdhc, SensorData) ->
    send_data(events, Mdhc, SensorData, [{async, true}]).
send_data(Mode, Mdhc, T0, SensorData, Opts) ->
    send_data(Mode, Mdhc, T0, SensorData, Opts, []).

send_data(Mode, Mdhc, T0, SensorData, Opts, ReqOpts) ->
    RpcArgs = #{
        method => setData,
        context => Mode,
        key => Mdhc#mdhc.app_key,
        opts => Opts,
        params => [{ns, T0} | SensorData]
    },
    call_method(Mdhc, setData, [{mode, Mode}], case Mdhc#mdhc.app_key of
        <<>> ->
            RpcArgs#{adminkey => Mdhc#mdhc.admin_key};
        _ ->
            RpcArgs
    end, ReqOpts).

send_data_vector(Mode, Mdhc, Data, Opts) ->
    send_data_vector(Mode, Mdhc, Data, Opts, []).

send_data_vector(Mode, Mdhc, TimeSeries, Opts, ReqOpts) ->
    RpcArgs = #{
        method => setData,
        context => Mode,
        key => Mdhc#mdhc.app_key,
        opts => Opts,
        params => TimeSeries
    },
    call_method(Mdhc, setData, [{mode, Mode}], case Mdhc#mdhc.app_key of
        <<>> ->
            RpcArgs#{adminkey => Mdhc#mdhc.admin_key};
        _ ->
            RpcArgs
    end, ReqOpts).

send_data(Mode, Mdhc, SensorData, Opts) ->
    RpcArgs = #{
        method => setData,
        context => Mode,
        key => Mdhc#mdhc.app_key,
        opts => Opts,
        params => send_data_genparams(SensorData)
    },
    call_method(Mdhc, setData, [{mode, Mode}], case Mdhc#mdhc.app_key of
        <<>> ->
            RpcArgs#{adminkey => Mdhc#mdhc.admin_key};
        _ ->
            RpcArgs
    end, []).

%% @doc Uploads data from sensors to server
%%      using the chunked transfer encoding.
%%
%% @spec send_events_data_chunked(Client :: mdhc(),
%%                                SensorData :: fun((term()) -> {ok, binary(), list()} |
%%                                                              {ok, binary(), list(), term()} |
%%                                                              {ok, list()} |
%%                                                              {ok, list(), term()} |
%%                                                              term()),
%%                                GeneratorState :: term()) ->
%%                                    Properties :: list() | {error, Reason :: term()}
send_events_data_chunked(Mdhc, SensorData, GeneratorState) ->
    send_data_chunked(events, Mdhc, SensorData, GeneratorState, [], undefined).

%% @doc Uploads data from sensors to server using an 'events' mode
%%      using the chunked transfer encoding.
%%
%% @spec send_events_data_chunked(Client :: mdhc(),
%%                                SensorData :: fun((term()) -> {ok, binary(), list()} |
%%                                                              {ok, binary(), list(), term()} |
%%                                                              {ok, list()} |
%%                                                              {ok, list(), term()} |
%%                                                              term()),
%%                                GeneratorState :: term(),
%%                                Options :: list(),
%%                                Timeout :: positive_integer() | infinity) ->
%%                                    Properties :: list() | {error, Reason :: term()}
send_events_data_chunked(Mdhc, SensorData, GeneratorState, Options, Timeout) when ?IS_TIMEOUT(Timeout) ->
    send_data_chunked(events, Mdhc, SensorData, GeneratorState, Options, Timeout).

%% @doc Uploads GeoJSON/TopoJSON/KML data from sensors to server.
%%
%%      Data swimline is determined by the application key.
%%      Payload is binary value in either GeoJSON, TopoJSON or KML format.
%%      Please see additional details about sent data in README.
%% @spec send_events_geo_data(Client :: mdhc(),
%%                            GeoJSONorKML :: binary() | {struct, list()}) ->
%%                              Properties :: list() | {error, Reason :: term()}
send_events_geo_data(Mdhc, GeoJSONorKML) when is_binary(GeoJSONorKML) ->
    call_method(Mdhc, setData, [{mode, geo_events}], GeoJSONorKML);

send_events_geo_data(Mdhc, GeoJSONorKML) ->
    call_method(Mdhc, setData, [{mode, geo_events}], jsx:encode(GeoJSONorKML)).

%% @doc Ping an 'events' service.
%%
%%      Server responses with 1 or with an error message if the service is unavailable.
%%
%%      Side effect of the ping() method is that any write operations for this application
%%      key, which are in progress at the moment of request, will be completed until the
%%      server responses with service status.
%% @spec ping_events_service(Client :: mdhc()) ->
%%                               Properties :: list() | {error, Reason :: term()}
ping_events_service(Mdhc) ->
    ping(events, Mdhc, undefined).

%% @doc Ping an 'events' service.
%%
%%      Server responses with 1 or with an error message if the service is unavailable.
%%      Timeout is either maximum number of milliseconds to wait, or 'infinity'.
%%
%%      Side effect of the ping() method is that any write operations for this application
%%      key, which are in progress at the moment of request, will be completed until the
%%      server responses with service status.
%% @spec ping_events_service(Client :: mdhc(), Timeout :: positive_integer() | infinity) ->
%%                               Properties :: list() | {error, Reason :: term()}
ping_events_service(Mdhc, Timeout) when ?IS_TIMEOUT(Timeout) ->
    ping(events, Mdhc, Timeout).

ping(Mode, Mdhc, Timeout) ->
    call_method(Mdhc, ping, [{mode, Mode}], jsx:encode(#{
        method => ping,
        context => Mode,
        key => Mdhc#mdhc.app_key,
        params => if
            ?IS_TIMEOUT(Timeout) ->
                #{timeout => Timeout};
            true ->
                #{}
        end
    })).

%% @doc Queries sensor data from server using a query language syntax v1.
%%
%%      The Script argument is a string, containing one or more query language
%%      (QL) statments. Syntax requires a semicolon at the end of each QL statement.
%%
%%      Returned value depends on script content and can be either json/text sensor
%%      data for SELECT statement, or result of evaluation of other query statments.
%%
%%      Mode of querying (streaming or events), as well as application keys to use,
%%      can be switched inside the script using query language statements.
%% @spec events_query(Client :: mdhc(), Script :: string()) ->
%%                          Result :: list() | binary() | integer() |
%%                          {error, Reason :: term()} |
%%                          {postpone, Uuid :: integer() | binary()}
events_query(Mdhc, Script) ->
    ql_query(Mdhc, [{mode, events}], Script).

%% @doc Queries 'events' sensor data from server using a query language syntax v1
%%      with streaming body from server to client.
%%
%%      The Script argument is a string, containing one or more query language
%%      (QL) statments. Syntax requires a semicolon at the end of each QL statement.
%%
%%      Returned value depends on script content and can be either json/text sensor
%%      data for SELECT statement, or result of evaluation of other query statments.
%%
%%      Mode of querying (streaming or events), as well as application keys to use,
%%      can be switched inside the script using query language statements.
%% @spec events_query_sb(Client :: mdhc(), Script :: string()) ->
%%                          Result :: list() | binary() | integer() |
%%                          {error, Reason :: term()} |
%%                          {postpone, Uuid :: integer() | binary()}
events_query_sb(Mdhc, Script) ->
    ql_query(Mdhc, [{mode, events}, {stream, 1}], Script).

%% @doc Queries 'events' sensor data from server using a query language syntax v1 or v2.
%%
%%      The Script argument is a string, containing one or more query language
%%      (QL) statments. Syntax requires a semicolon at the end of each QL statement.
%%
%%      Returned value depends on script content and can be either json/text sensor
%%      data for SELECT statement, or result of evaluation of other query statments.
%%
%%      Mode of querying (streaming or events), as well as application keys to use,
%%      can be switched inside the script using query language statements.
%%
%%      Query Language version is defined by Ver argument.
%% @spec events_query(Client :: mdhc(), Script :: string(), Ver :: integer()) ->
%%                          Result :: list() | binary() | integer() |
%%                          {error, Reason :: term()} |
%%                          {postpone, Uuid :: integer() | binary()}
events_query(Mdhc, Script, Ver) when is_integer(Ver) ->
    ql_query(Mdhc, [{mode, events}, {ver, Ver}], Script).

%% @doc Queries 'events' sensor data from server using a query language syntax v1 or v2
%%      with streaming body from server to client.
%%
%%      The Script argument is a string, containing one or more query language
%%      (QL) statments. Syntax requires a semicolon at the end of each QL statement.
%%
%%      Returned value depends on script content and can be either json/text sensor
%%      data for SELECT statement, or result of evaluation of other query statments.
%%
%%      Mode of querying (streaming or events), as well as application keys to use,
%%      can be switched inside the script using query language statements.
%%
%%      Query Language version is defined by Ver argument.
%% @spec events_query(Client :: mdhc(), Script :: string(), Ver :: integer()) ->
%%                          Result :: list() | binary() | integer() |
%%                          {error, Reason :: term()} |
%%                          {postpone, Uuid :: integer() | binary()}
events_query_sb(Mdhc, Script, Ver) when is_integer(Ver) ->
    ql_query(Mdhc, [{mode, events}, {ver, Ver}, {stream, 1}], Script).

%% @doc Asynchronously queries 'events' sensor data from server using a query language syntax.
%%
%%      The Script argument is a string, containing one or more query language
%%      (QL) statments. Syntax requires a semicolon at the end of each QL statement.
%%
%%      Returned value depends on script content and can be either json/text sensor
%%      data for SELECT statement, or result of evaluation of other query statments.
%%
%%      Mode of querying (streaming or events), as well as application keys to use,
%%      can be switched inside the script using query language statements.
%% @spec events_query(Client :: mdhc(), Script :: string()) ->
%%                          Result :: list() | binary() | integer() |
%%                          {error, Reason :: term()} |
%%                          {postpone, Uuid :: integer() | binary()}
async_events_query(Mdhc, Script) ->
    ql_query(Mdhc, [{mode, events}, {async, true}], Script).

%% @doc Asynchronously queries sensor data from server using a query language syntax
%%      with streaming body from server to client.
%%
%%      The Script argument is a string, containing one or more query language
%%      (QL) statments. Syntax requires a semicolon at the end of each QL statement.
%%
%%      Returned value depends on script content and can be either json/text sensor
%%      data for SELECT statement, or result of evaluation of other query statments.
%%
%%      Mode of querying (streaming or events), as well as application keys to use,
%%      can be switched inside the script using query language statements.
%% @spec events_query(Client :: mdhc(), Script :: string()) ->
%%                          Result :: list() | binary() | integer() |
%%                          {error, Reason :: term()} |
%%                          {postpone, Uuid :: integer() | binary()}
async_events_query_sb(Mdhc, Script) ->
    ql_query(Mdhc, [{mode, events}, {async, true}, {stream, 1}], Script).

%% @doc Asynchronously queries sensor data from server using a query language syntax.
%%
%%      The Script argument is a string, containing one or more query language
%%      (QL) statments. Syntax requires a semicolon at the end of each QL statement.
%%
%%      Returned value depends on script content and can be either json/text sensor
%%      data for SELECT statement, or result of evaluation of other query statments.
%%
%%      Mode of querying (streaming or events), as well as application keys to use,
%%      can be switched inside the script using query language statements.
%%
%%      Query Language version is defined by Ver argument.
%% @spec events_query(Client :: mdhc(), Script :: string(), Ver :: integer()) ->
%%                          Result :: list() | binary() | integer() |
%%                          {error, Reason :: term()} |
%%                          {postpone, Uuid :: integer() | binary()}
async_events_query(Mdhc, Script, Ver) when is_integer(Ver) ->
    ql_query(Mdhc, [{mode, events}, {async, true}, {ver, Ver}], Script).

%% @doc Asynchronously queries 'events' sensor data from server using a query language
%%      syntax with streaming body from server to client.
%%
%%      The Script argument is a string, containing one or more query language
%%      (QL) statments. Syntax requires a semicolon at the end of each QL statement.
%%
%%      Returned value depends on script content and can be either json/text sensor
%%      data for SELECT statement, or result of evaluation of other query statments.
%%
%%      Mode of querying (streaming or events), as well as application keys to use,
%%      can be switched inside the script using query language statements.
%%
%%      Query Language version is defined by Ver argument.
%% @spec events_query(Client :: mdhc(), Script :: string(), Ver :: integer()) ->
%%                          Result :: list() | binary() | integer() |
%%                          {error, Reason :: term()} |
%%                          {postpone, Uuid :: integer() | binary()}
async_events_query_sb(Mdhc, Script, Ver) ->
    ql_query(Mdhc, [{mode, events}, {async, true}, {ver, Ver}, {stream, 1}], Script).

%%------------------------------------------------------------------------------
