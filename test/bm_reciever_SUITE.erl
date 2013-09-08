-module(bm_reciever_SUITE).

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
         my_test_case/1]).

-include_lib("common_test/include/ct.hrl").

%%%===================================================================
%%% Common Test callbacks
%%%===================================================================

all() ->
    [my_test_case].

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
    meck:new(bm_db),
    meck:new(bm_dispatcher),
    meck:new(transport),
    meck:new(bm_sender),
    meck:expect(bm_db, lookup, fun(Tab, Key) -> [Tab, Key] end),
    meck:expect(transport, send, fun(S, Data) -> ok end),
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%%===================================================================
%%% Test cases
%%%===================================================================

my_test_case() ->
    [].

test_process_object(_Config) ->
    meck:expect(bm_db, lookup, fun(Tab, Key) -> [] end),
    ok = bm_reciever:process_object(<<"test">>, <<(crypto:rend_bytes(8)):64/bits, 0:32/big-integer, 123456789:32/big-integer, 1, <<"testtesttest">>, #state{stream=1}, fun(Hash) -> ok end),
    ok.
