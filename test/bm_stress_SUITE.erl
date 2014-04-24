-module(bm_stress_SUITE).

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
-export([encryptor_race_test/0,
         encryptor_race_test/1]).

-include_lib("common_test/include/ct.hrl").

%%%===================================================================
%%% Common Test callbacks
%%%===================================================================

all() ->
    [encryptor_race_test].

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
    application:start(crypto),
    bm_db:start_link(),
    bm_pow:start_link(),
    bm_dispatcher:start_link(),
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%%===================================================================
%%% Test cases
%%%===================================================================

encryptor_race_test() ->
    [].

encryptor_race_test(_Config) ->
    Renge = lists:seq(100),
    lists:foreach(fun(X)->
                          bitmessage:send_message(<<"BM-2DC1KLUL4ZhVFaW258UjCPjNV7t4F4amZc">>,
                                                  <<"BM-2DAH8StoW625wFrxWoj61ALG2vDM4SEwcW">>,
                                                  integer_to_binary(X),
                                                  <<"test">>)
                  end, Renge),
    ok.
