-module(bm_reciever_SUITE).

-include("../include/bm.hrl").
-record(init_stage, {verack_sent=false,verack_recv=false}).
-record(state, {socket, transport, version, stream = 1, init_stage = #init_stage{}, remote_streams, remote_addr}).


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
-export([%test_process_object/0,
    test_process_object_new/1,
    test_process_object_msg/1,
    test_process_object_not_insert/1,
    test_analyse_packet_pubkey/1
    ]).

-include_lib("common_test/include/ct.hrl").

%%%===================================================================
%%% Common Test callbacks
%%%===================================================================

all() ->
    [test_process_object_new,
     test_process_object_msg, 
     test_process_object_not_insert, 
     test_analyse_packet_pubkey].

suite() ->
    [{timestamp, {seconds, 30}}].

groups() ->
    [].

init_per_suite(Config) ->
    ok=application:start(crypto),
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
    meck:new(bm_db),
    meck:new(bm_dispatcher),
    meck:new(transport, [non_strict]),
    meck:new(bm_sender),
    meck:expect(transport, send, fun(S, Data) -> {ok, S, Data} end),
    Config.

end_per_testcase(_TestCase, _Config) ->
    meck:unload(bm_db),
    meck:unload(bm_dispatcher),
    meck:unload(transport),
    meck:unload(bm_sender),
    ok.

%%%===================================================================
%%% Test cases
%%%===================================================================

%test_process_object() ->
%    [].

test_process_object_new(_Config) ->
    OKCTime =  bm_types:timestamp() +  crypto:rand_uniform(-300,0),
    ErCTime =  bm_types:timestamp() + crypto:rand_uniform(0,300) + 30000,
    ErCTime1 = bm_types:timestamp() + crypto:rand_uniform(-300,300) - 3000 *48*36,
    meck:expect(bm_db, lookup, fun(Tab, Key) -> [] end),
    meck:expect(bm_db, insert, fun(inventory, Key) -> ok end),
    ok = bm_reciever:process_object(<<"test">>, 
                                    <<(crypto:rand_bytes(8)):64/bits,
                                      0:32/big-integer, 
                                      OKCTime:32/big-integer, 
                                      1/integer, 
                                      1,
                                      <<"testtesttest">>/bytes>>,
                                    #state{stream=1}, fun(Hash) -> ok end),
    ok = bm_reciever:process_object(<<"test">>, 
                                    <<(crypto:rand_bytes(8)):64/bits,
                                      OKCTime:32/big-integer, 
                                      1/integer, 
                                      1,
                                      <<"testtesttest">>/bytes>>,
                                    #state{stream=1}, fun(Hash) -> ok end),
    true = meck:validate(bm_db),
    true=meck:called(bm_db, lookup,[inventory, '_']),
    true=meck:called(bm_db, insert,[inventory, '_']).

test_process_object_not_insert(_Config) ->
    OKCTime =  bm_types:timestamp() +  crypto:rand_uniform(-300,0),
    ErCTime =  bm_types:timestamp() + crypto:rand_uniform(0,300) + 30000,
    ok=meck:expect(bm_db, lookup, fun(Tab, Key) -> [Tab] end),
    ok=meck:expect(bm_db, insert, fun(Tab, Key) -> meck:exception(error, insertion_occured) end),
    #state{stream=1} = bm_reciever:process_object(<<"test">>, 
                                    <<(crypto:rand_bytes(8)):64/bits,
                                      0:32/big-integer, 
                                      OKCTime:32/big-integer, 
                                      1/integer, 
                                      1,
                                      <<"testtesttest">>/bytes>>,
                                    #state{stream=1}, fun(Hash) -> ok end),
    true=meck:called(bm_db, lookup,[inventory, '_']),

    meck:expect(bm_db, lookup, fun(Tab, Key) -> [] end),
    ok=meck:expect(bm_db, insert, fun(Tab, Key) -> meck:exception(error, insertion_occured) end),
    #state{stream=2} = bm_reciever:process_object(<<"test">>, 
                                    <<(crypto:rand_bytes(8)):64/bits,
                                      0:32/big-integer, 
                                      ErCTime:32/big-integer, 
                                      1/integer, 
                                      1,
                                      <<"testtesttest">>/bytes>>,
                                    #state{stream=2}, fun(Hash) -> ok end),
    0 = meck:num_calls(bm_db, insert, [inventory, '_']).

test_process_object_msg(_Config) ->
    OKCTime =  bm_types:timestamp() +  crypto:rand_uniform(-300,0),
    ErCTime =  bm_types:timestamp() + crypto:rand_uniform(0,300) + 30000,
    ok=meck:expect(bm_db, lookup, fun(Tab, Key) -> [] end),
    ok=meck:expect(bm_db, insert, fun(Tab, Key) -> ok end),
    ok = bm_reciever:process_object(<<"msg">>, 
                                    <<(crypto:rand_bytes(8)):64/bits,
                                      0:32/big-integer, 
                                      OKCTime:32/big-integer, 
                                      1/integer, 
                                      <<"testtesttest">>/bytes>>,
                                    #state{stream=1}, fun(Hash) -> ok end),
    true=meck:called(bm_db, lookup,[inventory, '_']).

test_analyse_packet_pubkey(_Config) ->
    {MSec, Sec, _} = now(),
    OKCTime = trunc(MSec * 1.0e6 + Sec + crypto:rand_uniform(-300,0)),
    meck:expect(bm_db, lookup, fun(Tab, Key) -> [] end),
    meck:expect(bm_db, insert, fun(pubkey, _) -> ok;
            (inventory, _) -> ok 
        end),
    #state{init_stage=#init_stage{verack_sent=true, verack_recv=true}} = bm_reciever:analyse_packet(<<"pubkey">>,  150,
                                    <<(crypto:rand_bytes(8)):64/bits,
                                      0:32/big-integer, 
                                      OKCTime:32/big-integer, 
                                      3/integer, 
                                      1,
                                      1:32/big-integer,
                                      (crypto:rand_bytes(128))/bytes>>, #state{init_stage=#init_stage{verack_sent=true, verack_recv=true}}),
    true=meck:called(bm_db, insert, [pubkey, '_']),
    meck:expect(bm_db, lookup, fun(Tab, Key) -> [ok] end),
    #state{init_stage=#init_stage{verack_sent=true, verack_recv=true}} = bm_reciever:analyse_packet(<<"pubkey">>,  150,
                                    <<(crypto:rand_bytes(8)):64/bits,
                                      0:32/big-integer, 
                                      OKCTime:32/big-integer, 
                                      3/integer, 
                                      1,
                                      1:32/big-integer,
                                      (crypto:rand_bytes(128))/bytes>>, #state{init_stage=#init_stage{verack_sent=true, verack_recv=true}}),
    1 = meck:num_calls(bm_db, insert, [pubkey, '_']).
