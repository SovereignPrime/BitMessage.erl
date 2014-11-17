-module(bm_types_SUITE).

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
         integer_to_bytes/0,
         integer_to_bytes/1,
         decode_encode_list/0,
         decode_encode_list/1,
         decode_encode_network/0,
         decode_encode_network/1,
         decode_encode_varint/0,
         decode_encode_varint/1,
         decode_encode_varstr/0,
         decode_encode_varstr/1,
         encode_list/0,
         encode_list/1,
         encode_network/0,
         encode_network/1,
         encode_varint/0,
         encode_varint/1,
         encode_varstr/0,
         encode_varstr/1
        ]).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include("../include/bm.hrl").


%%%===================================================================
%%% Common Test callbacks
%%%===================================================================

all() ->  % {{{1
    [
     integer_to_bytes,
     decode_encode_list,
     decode_encode_network,
     decode_encode_varint,
     decode_encode_varstr,
     encode_list,
     encode_network,
     encode_varint,
     encode_varstr
    ].

suite() ->  % {{{1
    [{timetrap, {seconds, 30}}].

groups() ->  % {{{1
    [].

init_per_suite(Config) ->  % {{{1
    Config.

end_per_suite(_Config) ->  % {{{1
    ok.

group(_GroupName) ->  % {{{1
    [].

init_per_group(_GroupName, Config) ->  % {{{1
    Config.

end_per_group(_GroupName, _Config) ->  % {{{1
    ok.

init_per_testcase(_TestCase, Config) ->  % {{{1
    Config.

end_per_testcase(_TestCase, _Config) ->  % {{{1
    ok.

%%%===================================================================
%%% Test cases
%%%===================================================================


integer_to_bytes() ->  % {{{1
    [].

integer_to_bytes(_Config) ->  % {{{1
        ?_assert(integer_to_bytes(crypto:bytes_to_integer(<<"TEST">>)) == <<"TEST">>).

decode_encode_list() ->  % {{{1
    [].

decode_encode_list(_Config) ->  % {{{1
    eunit:test({generator, fun decode_encode_list_test_/0}).

decode_encode_network() ->  % {{{1
    [].
decode_encode_network(_Config) ->  % {{{1
    eunit:test({generator, fun decode_encode_network_test_/0}).

decode_encode_varint() ->  % {{{1
    [].
decode_encode_varint(_Config) ->  % {{{1
    eunit:test({generator, fun decode_encode_varint_test_/0}).

decode_encode_varstr() ->  % {{{1
    [].
decode_encode_varstr(_Config) ->  % {{{1
    eunit:test({generator, fun decode_encode_varstr_test_/0}).

encode_list() ->  % {{{1
    [].
encode_list(_Config) ->  % {{{1
    eunit:test({generator, fun encode_list_test_/0}).

encode_network() ->  % {{{1
    [].
encode_network(_Config) ->  % {{{1
    eunit:test({generator, fun encode_network_test_/0}).

encode_varint() ->  % {{{1
    [].

encode_varint(_Config) ->  % {{{1
    eunit:test({generator, fun encode_varint_test_/0}).

encode_varstr() ->  % {{{1
    [].
encode_varstr(_Config) ->  % {{{1
    eunit:test({generator, fun encode_varstr_test_/0}).

%%%
%%% EUnit test generators
%%%

encode_varint_test_() ->  % {{{1
    [
        ?_assert(bm_types:encode_varint(10) == <<10>>),
        ?_assert(bm_types:encode_varint(253) == <<16#fd, 00, 253>>),
        ?_assert(bm_types:encode_varint(252) == <<252>>),
        ?_assert(bm_types:encode_varint(65535) == <<16#fd,16#ff, 16#ff>>),
        ?_assert(bm_types:encode_varint(65536) == <<16#fe, 00, 01, 00, 00>>),
        ?_assert(bm_types:encode_varint(4294967295) == <<16#fe, 16#ff, 16#ff, 16#ff, 16#ff>>),
        ?_assert(bm_types:encode_varint(4294967296) == <<16#ff, 00, 00, 00, 01, 00, 00, 00, 00>>)
        ].
decode_encode_varint_test_() ->  % {{{1
    [
        ?_assert(bm_types:decode_varint(bm_types:encode_varint(10))== {10, <<>>}),
        ?_assert(bm_types:decode_varint(bm_types:encode_varint(253))== {253, <<>>}),
        ?_assert(bm_types:decode_varint(bm_types:encode_varint(252))== {252, <<>>}),
        ?_assert(bm_types:decode_varint(bm_types:encode_varint(65535))== {65535, <<>>}),
        ?_assert(bm_types:decode_varint(bm_types:encode_varint(65536))== {65536, <<>>}),
        ?_assert(bm_types:decode_varint(bm_types:encode_varint(4294967295))== {4294967295, <<>>}),
        ?_assert(bm_types:decode_varint(bm_types:encode_varint(4294967296))== {4294967296, <<>>}),
        ?_assert(bm_types:decode_varint(<<(bm_types:encode_varint(4294967296))/bits, <<"test">>/bits>>)== {4294967296, <<"test">>})
        ].

encode_varstr_test_() ->  % {{{1
    [
        ?_assert(bm_types:encode_varstr("1234567890") == <<10,"1234567890">>)
        ].
decode_encode_varstr_test_() ->  % {{{1  % {{{1
    [
        ?_assert(bm_types:decode_varstr(bm_types:encode_varstr("TEST")) == {"TEST", <<>>})
                ].

encode_list_test_() ->  % {{{1
    [
        ?_assert(bm_types:encode_list([1,2,3,4,5,6,7,8,9,0], fun bm_types:encode_varint/1) == <<10, 1,2,3,4,5,6,7,8,9,0>>),
        ?_assert(bm_types:encode_list([1,255,3,4,5,65536,7,8,9,0], fun bm_types:encode_varint/1) == <<10, 1,(bm_types:encode_varint(255))/bytes,3,4,5,(bm_types:encode_varint(65536))/bytes,7,8,9,0>>),
        ?_assert(bm_types:encode_list(["a", "b"], fun([O]) -> <<O>> end) == <<2, "a", "b">>)
                ].

decode_encode_list_test_() ->  % {{{1
    [
        ?_assert(bm_types:decode_list(bm_types:encode_list([1,2,3,4,5,6,7,8,9,0], fun bm_types:encode_varint/1), fun bm_types:decode_varint/1) == {[1,2,3,4,5,6,7,8,9,0], <<>>}),
        ?_assert(bm_types:decode_list(bm_types:encode_list([1,255,3,4,5,65536,7,8,9,0], fun bm_types:encode_varint/1), fun bm_types:decode_varint/1) == {[1,255,3,4,5,65536,7,8,9,0], <<>>}),
        ?_assert(bm_types:decode_list(bm_types:encode_list(["a", "b"], fun([O]) -> <<O>> end), fun(<<O:8/integer, R/bytes>>)-> {[O], R}  end) == {["a", "b"], <<>>})
                ].

encode_network_test_() ->  % {{{1
    {ok, IP} = inet:parse_ipv4_address("127.0.0.1"),
    [
        ?_assert(bm_types:encode_network(#network_address{time=333, stream=1, ip=IP, port=8080, services=1} ) == <<333:64/big-integer, 1:32/big-integer, 1:64/big-integer, 0,0,0,0,0,0,0,0,0,0,255,255, 127,0,0,1, 8080:16/big-integer>>)
                ].

decode_encode_network_test_() ->  % {{{1
    {ok, IP} = inet:parse_ipv4_address("127.0.0.1"),
    [
        ?_assert(bm_types:decode_network(bm_types:encode_network(#network_address{time=333,
                                                                stream=1,
                                                                ip=IP,
                                                                port=8080,
                                                                services=1})) 
                 == {#network_address{time=333,
                                      stream=1,
                                      ip=IP,
                                      port=8080,
                                      services=1},
                     <<>>})
                ].
