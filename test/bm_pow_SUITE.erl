-module(bm_pow_SUITE).

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
-export([%my_test_case/0,
         test_make_check/1]).

-include_lib("common_test/include/ct.hrl").

%%%===================================================================
%%% Common Test callbacks
%%%===================================================================

all() ->
    [test_make_check].

suite() ->
    [{timetrap, {seconds, 300}}].

groups() ->
    [].

init_per_suite(Config) ->
    application:start(crypto),
    Config.

end_per_suite(_Config) ->
    application:stop(crypto),
    ok.

group(_GroupName) ->
    [].

init_per_group(_GroupName, Config) ->
    Config.

end_per_group(_GroupName, _Config) ->
    ok.

init_per_testcase(_TestCase, Config) ->
    bm_pow:start_link(),
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%%===================================================================
%%% Test cases
%%%===================================================================

my_test_case() ->
    [].

test_make_check(_Config) ->
    Data = crypto:rand_bytes(32),
    POW = bm_pow:make_pow(Data),
    true=bm_pow:check_pow(<<POW:64/big-integer, Data/bytes>>).
