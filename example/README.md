# TimeEngine Client Example

## Sample Run

    $ make && make run
    ===> Verifying dependencies...
    ===> Verifying dependencies...
    ===> Analyzing applications...
    ===> Compiling texample
    ===> Verifying dependencies...
    ===> Verifying dependencies...
    ===> Analyzing applications...
    ===> Compiling texample
    ===> Verifying dependencies...
    ===> Analyzing applications...
    ===> Compiling texample
    Erlang/OTP 24 [erts-12.0] [source] [64-bit] [smp:2:2] [ds:2:2:10] [async-threads:1] [jit]

    Eshell V12.0  (abort with ^G)
    1> texample:start().
    >>> loadind dependencies...
    ok
    2> texample_app:with_keycloak().
    =INFO REPORT==== 16-Oct-2021::17:32:53.059781 ===
    Query result: #{<<"data">> =>
                        [#{<<"_qsz">> => 165,<<"dur">> => 2,<<"mb">> => 0.08,
                           <<"ms">> => 10,<<"t0">> => 1634398370,
                           <<"unit">> => <<"c">>,<<"unit_step">> => 1,
                           <<"values">> =>
                               #{<<"0">> => #{<<"1634398371000000000">> => 100},
                                 <<"1">> =>
                                     #{<<"1634398371000000000">> => 200}}}]}
    ok
    3> texample_app:without_keycloak().
    =INFO REPORT==== 16-Oct-2021::17:33:03.793370 ===
    Query result: #{<<"data">> =>
                        [#{<<"_qsz">> => 165,<<"dur">> => 2,<<"mb">> => 0.08,
                           <<"ms">> => 52,<<"t0">> => 1634398380,
                           <<"unit">> => <<"c">>,<<"unit_step">> => 1,
                           <<"values">> =>
                               #{<<"0">> => #{<<"1634398381000000000">> => 100},
                                 <<"1">> =>
                                     #{<<"1634398381000000000">> => 200}}}]}
    ok

# Copyright
Copyright 2015—2021 QOMPLX, Inc. — All Rights Reserved.  No License Granted.
