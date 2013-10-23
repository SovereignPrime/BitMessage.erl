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
-export([my_test_case/0,
         decrypt_test/1]).

-include_lib("common_test/include/ct.hrl").

%%%===================================================================
%%% Common Test callbacks
%%%===================================================================

all() ->
    [decrypt_test].

suite() ->
    [{timetrap, {seconds, 30}}].

groups() ->
    [].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

group(_GroupName) ->
    [].

init_per_group(_GroupName, Config) ->
    Config.

end_per_group(_GroupName, _Config) ->
    ok.

init_per_testcase(_TestCase, Config) ->
    meck:new(bm_dispatcher),
    meck:expect(bm_dispatcher, message_arrived, fun(M, <<"test">>, <<"BM-GtjvocmYdaNZEzGHuABKTELKdC4QMJyg">>) -> io:format("Message: ~p~n", [M]) end),
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%%===================================================================
%%% Test cases
%%%===================================================================

my_test_case() ->
    [].

decrypt_test(_Config) ->
    {ok, Pid} = bm_message_decryptor:start_link(#privkey{address= <<"BM-GtjvocmYdaNZEzGHuABKTELKdC4QMJyg">>, pek= <<16#02,16#ba,16#27,16#44,16#e6,16#5c,16#cd,16#7b,16#19,16#54,16#b0,16#a3,16#3b,16#80,16#d7,16#5e,16#16,16#ca,16#b4,16#7f,16#2b,16#33,16#1f,16#f0,16#b6,16#d1,16#84,16#b7,16#19,16#83,16#da,16#85>>}),
    gen_server:cast(Pid, {decrypt, message, <<"test">>, <<16#bd,16#db,16#7c,16#28,16#29,16#b0,16#80,16#38,16#75,16#30,16#84,16#a2,16#f3,16#99,16#16,16#81,16#02,16#ca,16#00,16#20,16#02,16#93,16#21,16#3d,16#cf,16#13,16#88,16#b6,16#1c,16#2a,16#e5,16#cf,16#80,16#fe,16#e6,16#ff,16#ff,16#c0,16#49,16#a2,16#f9,16#fe,16#73,16#65,16#fe,16#38,16#67,16#81,16#3c,16#a8,16#12,16#92,16#00,16#20,16#df,16#94,16#68,16#6c,16#6a,16#fb,16#56,16#5a,16#c6,16#14,16#9b,16#15,16#3d,16#61,16#b3,16#b2,16#87,16#ee,16#2c,16#7f,16#99,16#7c,16#14,16#23,16#87,16#96,16#c1,16#2b,16#43,16#a3,16#86,16#5a,16#64,16#20,16#3d,16#5b,16#24,16#68,16#8e,16#25,16#47,16#bb,16#a3,16#45,16#fa,16#13,16#9a,16#5a,16#1d,16#96,16#22,16#20,16#d4,16#d4,16#8a,16#0c,16#f3,16#b1,16#57,16#2c,16#0d,16#95,16#b6,16#16,16#43,16#a6,16#f9,16#a0,16#d7,16#5a,16#f7,16#ea,16#cc,16#1b,16#d9,16#57,16#14,16#7b,16#f7,16#23,16#4c,16#08,16#ac,16#6c,16#93,16#c7,16#37,16#7b,16#ac,16#5a,16#2e,16#87,16#3d,16#d3,16#51,16#1b,16#12,16#7a,16#ff,16#6d,16#0d,16#16,16#38,16#cd,16#ae,16#49,16#89,16#c4,16#d2,16#fe,16#7d,16#e1>>}).
