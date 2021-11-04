%%-------------------------------------------------------------------4
%%
%% TimeEngine Erlang HTTP Client
%%
%% Copyright 2015-2021 -- QOMPLX, Inc. -- All Rights Reserved.  No License Granted.
%%
%%-------------------------------------------------------------------

-record(mdhc, {ip = "0.0.0.0",
               port = 8080,
               ws = undefined,
               ws_stream = undefined,
               app_key = <<>>,
               secret_key = <<>>,
               admin_key = <<>>,
               access_token = <<>>,
               access_token_type = <<>>,
               auth_url = <<>>,
               auth_client_id = <<>>,
               auth_client_secret = <<>>,
               options = []}).

-type(mdhc_ws_resp_id() :: undefined | number() | binary() | boolean()).
-type(mdhc_ws_resp() :: {ok, Id :: mdhc_ws_resp_id(), Result :: term()} |
                        {error, Id :: mdhc_ws_resp_id(), Reason :: term()}).

%%-------------------------------------------------------------------
%% Error codes in TimeEngine server response

-define(ERR_CODE_AUTH_NOKEY, 1000).
-define(ERR_CODE_AUTH_PERM, 1001).
-define(ERR_CODE_AUTH_OVERLOAD, 1002).

-define(ERR_CODE_SERVICE_DENY, 2000).
-define(ERR_CODE_SERVICE_TIMEOUT, 2001).
-define(ERR_CODE_SERVICE_BADTIMEOUT, 2002).

-define(ERR_CODE_API_EXPECT, 3000).
-define(ERR_CODE_API_UNKNOWNMETH, 3001).

-define(ERR_CODE_QL_SYNTAX, 4000).
-define(ERR_CODE_QL_FORMAT, 4001).
-define(ERR_CODE_QL_NIFMATH, 4002).
-define(ERR_CODE_QL_UNKNOWN_METH, 4003).
-define(ERR_CODE_QL_GENERAL, 4004).
-define(ERR_CODE_QL_FILE_NOTFOUND, 4005).
-define(ERR_CODE_QL_UNKNOWN_SUBJ, 4006).
-define(ERR_CODE_QL_LOGICS, 4007).
-define(ERR_CODE_QL_EXPR, 4008).
-define(ERR_CODE_QL_TIMELESS, 4009).
-define(ERR_CODE_QL_SIZE, 4010).
-define(ERR_CODE_QL_MATHFAIL, 4011).

-define(ERR_CODE_REQ_NODATA, 5900).
-define(ERR_CODE_REQ_SIZE, 5000).
-define(ERR_CODE_REQ_LOADID, 5001).
-define(ERR_CODE_REQ_TIMEOUT, 5002).
-define(ERR_CODE_REQ_INTERNAL, 5003).
-define(ERR_CODE_REQ_S3ID, 5004).

-define(ERR_CODE_DB_INSUFF, 6000).
-define(ERR_CODE_DB_DISCON, 6001).
-define(ERR_CODE_DB_TIMEOUT, 6002).
-define(ERR_CODE_DB_INTERNAL, 6002).

-define(ERR_CODE_AMQP_GENERAL, 7000).
-define(ERR_CODE_AMQP_SEND, 7001).

-define(ERR_CODE_INCOME_FORMAT, 8000).

-define(ERR_CODE_GENERAL, 9000).
-define(ERR_CODE_INTERNAL, 9001).
-define(ERR_CODE_OFFLINE, 9002).
-define(ERR_CODE_UNEXPECTED_TEST, 9003).

%%-------------------------------------------------------------------
