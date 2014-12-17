-module(bm_auth_SUITE).

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
         decode_encode_address/0,
         decode_encode_address/1,
         dual_sha/0,
         dual_sha/1,
         encode_address/0,
         encode_address/1,
         generate_ripe/0,
         generate_ripe/1,
         pubkey_test/0,
         pubkey_test/1
        ]).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include("../include/bm.hrl").

%%%===================================================================
%%% Common Test callbacks  % {{{1
%%%===================================================================

all() ->  % {{{2
    [
     decode_encode_address,
     dual_sha,
     encode_address,
     generate_ripe,
     pubkey_test
    ].

suite() ->  % {{{2
    [{timetrap, {seconds, 60}}].

groups() ->  % {{{2
    [].

init_per_suite(Config) ->  % {{{2
    Config.

end_per_suite(_Config) ->  % {{{2
    ok.

group(_GroupName) ->  % {{{2
    [].

init_per_group(_GroupName, Config) ->  % {{{2
    Config.

end_per_group(_GroupName, _Config) ->  % {{{2
    ok.

init_per_testcase(_TestCase, Config) ->  % {{{2
    Config.

end_per_testcase(_TestCase, _Config) ->  % {{{2
    ok.

%%%===================================================================
%%% Test cases  % {{{1
%%%===================================================================

dual_sha() ->  % {{{2
    [].
dual_sha(_Config) ->  % {{{2
    eunit:test({generator, fun dual_sha_test_/0}).

generate_ripe() ->  % {{{2
    [].
generate_ripe(_Config) ->  % {{{2
    eunit:test({generator, fun generate_ripe_test_/0}).

encode_address() ->  % {{{2
    [].
encode_address(_Config) ->  % {{{2
    eunit:test({generator, fun encode_address_test_/0}).

decode_encode_address() ->  % {{{2
    [].
decode_encode_address(_Config) ->  % {{{2
    eunit:test({generator, fun decode_encode_address_test_/0}).

pubkey_test() ->  % {{{2
    [].

pubkey_test(_Config) ->  % {{{2
    application:start(crypto),
    {Pub, Priv} = crypto:generate_key(ecdh, secp256k1),
    PubResult = bm_auth:pubkey(Priv),
    io:format("Gen: ~p~n Com: ~p~n", [Pub, PubResult]),
    ?_assert(PubResult == Pub).


%%% 
%%% EUnit test generators  % {{{1
%%%
dual_sha_test_() ->  % {{{2
    [
        ?_assert("0592a10584ffabf96539f3d780d776828c67da1ab5b169e9e8aed838aaecc9ed36d49ff1423c55f019e050c66c6324f53588be88894fef4dcffdb74b98e2b200" == bm_types:binary_to_hexstring(bm_auth:dual_sha("hello")))
        ].

generate_ripe_test_() ->  % {{{2
    [
        ?_assert("79a324faeebcbf9849f310545ed531556882487e" == bm_types:binary_to_hexstring(bm_auth:generate_ripe("hello")))
        ].

encode_address_test_() ->  % {{{2
    [
        ?_assert(bm_auth:encode_address(#address{version=2, stream=1, ripe = <<"12345678901234567890">>}) == <<"BM-4ZVsZN4foCh82rehBbDkHvRWdtEJyvNMBce">>),
        ?_assert(bm_auth:encode_address(2, 1, <<"12345678901234567890">>) == <<"BM-4ZVsZN4foCh82rehBbDkHvRWdtEJyvNMBce">>),
        ?_assert(bm_auth:encode_address(2, 1, <<0, "1234567890123456789">>) == <<"BM-onWacauk6NKp6MmuF6cBdaCFFKsozCr5v">>),
        ?_assert(bm_auth:encode_address(2, 1, <<0, 0, "123456789123456789">>) == <<"BM-BbnDboCVo5NwApkngoNwb2JZA1wSevkg">>)

        ].

decode_encode_address_test_() ->  % {{{2
    [
        ?_assert(bm_auth:decode_address(bm_auth:encode_address(#address{version=2, stream=1, ripe = <<"12345678901234567890">>})) == #address{version=2, stream=1, ripe = <<"12345678901234567890">>}),
        ?_assert(bm_auth:decode_address(bm_auth:encode_address(2, 1, <<"12345678901234567890">>)) == #address{version=2, stream=1, ripe= <<"12345678901234567890">>}),
        ?_assert(bm_auth:decode_address(bm_auth:encode_address(2, 1, <<0, "1234567890123456789">>)) == #address{version=2, stream=1, ripe= <<0, "1234567890123456789">>}),
        ?_assert(bm_auth:decode_address(bm_auth:encode_address(2, 1, <<0, 0, "123456789123456789">>)) == #address{version=2, stream=1, ripe= <<0, 0, "123456789123456789">>})

        ].
