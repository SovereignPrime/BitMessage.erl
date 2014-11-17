-module(base58_SUITE).

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
         encode_decode_test/0,
         encode_decode_test/1
        ]).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Common Test callbacks
%%%===================================================================

all() ->
    [
     encode_decode_test
    ].

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
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%%===================================================================
%%% Test cases
%%%===================================================================

encode_decode_test() ->
    [].

encode_decode_test(_Config) ->
    ok=eunit:test({generator, fun encode_decode_test_/0}).

encode_decode_test_() ->
    [?_assert(1234567890 =:= base58:decode(base58:encode(1234567890))),
     %?_assert("123456789" =:= base58:encode(base58:decode("123456789"))),
     ?_assert("a123456789" =:= base58:encode(base58:decode("a123456789"))),
     ?_assert(1 =:= base58:decode(base58:encode(1))),
     ?_assert(0 =:= base58:decode(base58:encode(0))),
     ?_assert("1" =:= base58:encode(0)),
     ?_assert(0 =:= base58:decode("1")),

     ?_assert(254 =:= base58:decode("5P")),
     ?_assert("4ZVsZN4foCh82rehBbDkHvRWdtEJyvNMBce" =:= base58:encode(base58:decode("4ZVsZN4foCh82rehBbDkHvRWdtEJyvNMBce"))),
     ?_assert("4ZVnFV7q49aFtUBMSXun2bgGxMhLYHEAHaC" =:= base58:encode(base58:decode("4ZVnFV7q49aFtUBMSXun2bgGxMhLYHEAHaC"))),
     ?_assert("4ZVnFV7q" =:= base58:encode(base58:decode("4ZVnFV7q"))),
     ?_assert(132595939334988 =:= base58:decode("1234567891")),
     ?_assert(2286136885086 =:= base58:decode("123456789")),
     ?_assert(7690564481429305 =:= base58:decode("12345678912")),
     ?_assert(7690564481429860 =:= base58:decode("123456789Ab")),
     ?_assert("5P" =:= base58:encode(254))
    ].
