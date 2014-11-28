-module(bm_decryptor_SUITE).
-include("../include/bm.hrl").

%% API
-export([all/0,
         suite/0,
         groups/0,
         init_per_suite/1,
         end_per_suite/1,
         group/1,
         init_per_group/2,
         end_per_group/2,
         init_per_testcase/2,
         end_per_testcase/2]).

%% Test cases
-export([
         decrypt_test/0,
         decrypt_test/1,
         new_decrypt_test/0,
         new_decrypt_test/1
        ]).

-include_lib("common_test/include/ct.hrl").

%%%===================================================================
%%% Common Test callbacks % {{{1
%%%===================================================================

all() -> % {{{2
    [
     new_decrypt_test
    ].

suite() -> % {{{2
    [{timetrap, {seconds, 30}}].

groups() -> % {{{2
    [].

init_per_suite(Config) -> % {{{2
    Config.

end_per_suite(_Config) -> % {{{2
    ok.

group(_GroupName) -> % {{{2
    [].

init_per_group(_GroupName, Config) -> % {{{2
    Config.

end_per_group(_GroupName, _Config) -> % {{{2
    ok.

init_per_testcase(_TestCase, Config) -> % {{{2
    application:start(crypto),
    meck:new(bm_dispatcher),
    Config.

end_per_testcase(_TestCase, _Config) -> % {{{2
    application:stop(crypto),
    ok.

%%%===================================================================
%%% Test cases  % {{{1
%%%===================================================================

decrypt_test() ->  % {{{2
    [].

decrypt_test(_Config) ->  % {{{2
    meck:expect(bm_dispatcher, message_arrived, fun(M, <<"test">>, <<"BM-GtjvocmYdaNZEzGHuABKTELKdC4QMJyg">>) -> io:format("Message: ~p~n", [M]) end),
    {ok, Pid} = bm_message_decryptor:start_link(#privkey{address= <<"BM-GtjvocmYdaNZEzGHuABKTELKdC4QMJyg">>, pek= <<16#02,16#ba,16#27,16#44,16#e6,16#5c,16#cd,16#7b,16#19,16#54,16#b0,16#a3,16#3b,16#80,16#d7,16#5e,16#16,16#ca,16#b4,16#7f,16#2b,16#33,16#1f,16#f0,16#b6,16#d1,16#84,16#b7,16#19,16#83,16#da,16#85>>}),
    gen_server:cast(Pid, {decrypt, message, <<"test">>, <<16#bd,16#db,16#7c,16#28,16#29,16#b0,16#80,16#38,16#75,16#30,16#84,16#a2,16#f3,16#99,16#16,16#81,16#02,16#ca,16#00,16#20,16#02,16#93,16#21,16#3d,16#cf,16#13,16#88,16#b6,16#1c,16#2a,16#e5,16#cf,16#80,16#fe,16#e6,16#ff,16#ff,16#c0,16#49,16#a2,16#f9,16#fe,16#73,16#65,16#fe,16#38,16#67,16#81,16#3c,16#a8,16#12,16#92,16#00,16#20,16#df,16#94,16#68,16#6c,16#6a,16#fb,16#56,16#5a,16#c6,16#14,16#9b,16#15,16#3d,16#61,16#b3,16#b2,16#87,16#ee,16#2c,16#7f,16#99,16#7c,16#14,16#23,16#87,16#96,16#c1,16#2b,16#43,16#a3,16#86,16#5a,16#64,16#20,16#3d,16#5b,16#24,16#68,16#8e,16#25,16#47,16#bb,16#a3,16#45,16#fa,16#13,16#9a,16#5a,16#1d,16#96,16#22,16#20,16#d4,16#d4,16#8a,16#0c,16#f3,16#b1,16#57,16#2c,16#0d,16#95,16#b6,16#16,16#43,16#a6,16#f9,16#a0,16#d7,16#5a,16#f7,16#ea,16#cc,16#1b,16#d9,16#57,16#14,16#7b,16#f7,16#23,16#4c,16#08,16#ac,16#6c,16#93,16#c7,16#37,16#7b,16#ac,16#5a,16#2e,16#87,16#3d,16#d3,16#51,16#1b,16#12,16#7a,16#ff,16#6d,16#0d,16#16,16#38,16#cd,16#ae,16#49,16#89,16#c4,16#d2,16#fe,16#7d,16#e1>>}),
meck:wait(bm_dispatcher, message_arrived, '_', 1500).

new_decrypt_test() ->  % {{{2
    [].

new_decrypt_test(_Config) ->  % {{{2
    PK = #privkey{
            hash = <<87,80,73,58,203,124,116,75,140,153,145,217,181,199,
                     85,141,249,51,181>>,
            enabled=true,
            label=test,
            address = <<"BM-2D8uEB6d5KVrm3TZYMmLBS63RE6CTzZiRu">>,
            psk = <<110,162,71,114,180,200,139,164,148,156,8,203,145,72,149,
                    132,40,15,6,62,210,128,171,97,254,17,46,204,103,161,20,142>>,
            pek = <<234,172,119,60,201,241,191,178,19,125,23,77,105,202,22,16,203,
                    98,136,67,77,160,38,42,137,62,54,132,232,83,231,145>>,
            time = 1413446594,
            public = <<156,164,82,250,230,83,198,254,81,224,238,190,109,53,136,
                       180,15,70,174,104,32,210,67,20,106,97,240,47,127,102,206,186,
                       52,44,121,27,86,84,65,114,49,178,230,163,30,90,66,147,16,
                       180,250,8,87,208,102,52,186,53,255,157,26,144,237,31,52,151,
                       243,8,150,18,116,15,29,175,229,199,26,157,195,242,80,118,233,
                       214,48,34,233,216,242,255,66,31,96,150,160,96,91,164,135,152,
                       253,29,219,139,66,127,204,133,150,91,37,36,239,206,203,192,
                       107,196,7,112,117,140,47,232,12,201,156,138>>},
    {ok, PID} = bm_message_decryptor:start_link(PK),
    {ok, MSG} = file:read_file("../../test/data/msg5.bin"),
    meck:expect(bm_dispatcher,
                message_arrived,
                fun(M,
                    <<"test">>,
                    _) ->
                        io:format("Message: ~p~n", [M]) 
                end),
    gen_server:cast(PID, {decrypt, message, <<"test">>, MSG}),
    meck:wait(bm_dispatcher, message_arrived, '_', 1500).

