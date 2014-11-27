-module(bm_reciever_SUITE).

-include("../include/bm.hrl").
-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

%% Records {{{1
-record(init_stage,
        {verack_sent=true,
         verack_recv=true}).

-record(state,
        {socket,
         transport=test,
         version,
         stream = 1,
         init_stage = #init_stage{},
         remote_streams,
         remote_addr}).

%% API  {{{1
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

%% Test cases  {{{1
-export([
        version_packet/0,
        version_packet/1,
        verack_packet/0,
        verack_packet/1,
        addr_packet/0,
        addr_packet/1,
        inv_packet/0,
        inv_packet/1,
        getdata_packet/0,
        getdata_packet/1,
        object_packet_test/0,
        object_packet_test/1
    ]).
%% }}}

%%%===================================================================
%%% Common Test callbacks  {{{1
%%%===================================================================

all() ->  % {{{2
    [
     version_packet,
     verack_packet,
     addr_packet,
     inv_packet,
     getdata_packet,
     object_packet_test
    ].

suite() ->  % {{{2
    [{timestamp, {seconds, 300}}].

groups() ->  % {{{2
    [].

init_per_suite(Config) ->  % {{{2
    Config.

end_per_suite(Config) ->  % {{{2
    ok.

group(_GroupName) ->  % {{{2
    [].

init_per_group(_GroupName, Config) ->  % {{{2
    Config.

end_per_group(_GroupName, _Config) ->  % {{{2
    ok.

init_per_testcase(TestCase, Config) ->  % {{{2
    meck:new(inet, [unstick, passthrough]),
    meck:expect(inet, peername, fun(socket) ->
                                        {ok, {{127,0,0,1}, 5432}}
                                end),
    meck:expect(inet, sockname, fun(socket) ->
                                        {ok, {{127,0,0,1}, 5432}}
                                end),
    meck:new(test, [non_strict]),
    meck:expect(test, send, fun(Socket, MSG) ->
                                    io:format("~p~n", [MSG])
                            end),
    meck:new(bm_db),
    meck:new(bm_message_creator, [passthrough]),
    meck:new(bm_message_encryptor),
    meck:new(bm_message_decryptor),
    meck:expect(bm_db, lookup, fun(inventory, I) ->
                                       io:format("~p~n", [I]),
                                       [];
                                  (privkey, _) ->
                                       []
                            end),
    meck:expect(bm_db, insert, fun(inventory, _) ->
                                       ok
                            end),
    meck:expect(bm_message_creator, create_inv, fun(_) ->
                                                        <<"TEST_MSG">>
                                                end),

    meck:new(bm_sender),
    meck:new(bm_reciever, [passthrough]),
    meck:new(bm_pow),
    meck:expect(bm_sender, send_broadcast, fun(_) ->
                                                   ok
                                                end),
    Config.

end_per_testcase(_TestCase, Config) ->  % {{{2
    meck:unload(),
    ok.

%%%===================================================================
%%% Test cases  {{{1
%%%===================================================================

%%====================================================================
%% Objects tests  {{{1
%%====================================================================
version_packet() ->  % {{{2
    [].

version_packet(Config) ->  % {{{2
    Socket = socket,
    MSG = <<0,0,0,3,0,0,0,0,0,0,0,1,0,0,0,0,84,71,44,79,0,0,0,0,0,0,0,1,0,0,0,0,
            0,0,0,0,0,0,255,255,94,50,253,51,201,131,0,0,0,0,0,0,0,1,0,0,0,0,0,
            0,0,0,0,0,255,255,127,0,0,1,32,252,115,170,57,172,72,126,34,107,20,
            47,80,121,66,105,116,109,101,115,115,97,103,101,58,48,46,52,46,50,
            47,1,1>>,
    #state{version=3,
           init_stage=#init_stage{verack_sent=true,
                                  verack_recv=false},
           remote_streams=[1],
           remote_addr={network_address,{127,0,0,1},8444,1413950543,1,1}
          } = bm_reciever:analyse_packet(<<"version",
                                           0:5/unit:8>>,
                                         size(MSG),
                                         MSG,
                                         #state{transport=test,
                                                socket=Socket,
                                               init_stage=#init_stage{
                                                            verack_recv=false,
                                                            verack_sent=false}}).

verack_packet() ->  % {{{2
    [].

verack_packet(_Config) ->  % {{{2
    #state{
      init_stage=#init_stage{verack_recv=true}
      } = bm_reciever:analyse_packet(<<"verack",
                                       0:6/unit:8>>,
                                     0,
                                     <<>>,
                                     #state{
                                        init_stage=#init_stage{
                                                      verack_recv=false,
                                                      verack_sent=false}}).

addr_packet() ->  % {{{2
    [].

addr_packet(_Config) ->  % {{{2
    MSG = <<13,0,0,0,0,84,71,200,154,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,
            255,255,84,73,186,110,32,252,0,0,0,0,84,71,210,15,0,0,0,1,0,0,0,0,0,0,
            0,1,0,0,0,0,0,0,0,0,0,0,255,255,46,177,33,177,32,252,0,0,0,0,84,71,214,
            236,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,255,255,72,240,217,54,
            32,252,0,0,0,0,84,71,210,66,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,
            0,255,255,84,169,125,156,32,252,0,0,0,0,84,71,212,173,0,0,0,1,0,0,0,0,
            0,0,0,1,0,0,0,0,0,0,0,0,0,0,255,255,24,6,53,48,32,252,0,0,0,0,84,71,
            218,210,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,255,255,146,228,
            112,252,33,0,0,0,0,0,84,71,201,156,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,
            0,0,0,0,255,255,195,154,243,53,35,90,0,0,0,0,84,71,185,170,0,0,0,1,0,0,
            0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,255,255,104,4,118,65,32,252,0,0,0,0,84,
            71,214,206,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,255,255,37,221,
            161,235,32,252,0,0,0,0,84,71,189,68,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,
            0,0,0,0,0,255,255,153,37,29,239,32,252,0,0,0,0,84,71,204,44,0,0,0,1,0,
            0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,255,255,24,42,199,77,32,252,0,0,0,0,
            84,71,214,229,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,255,255,195,
            62,15,242,32,252,0,0,0,0,84,71,180,20,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,
            0,0,0,0,0,0,255,255,95,208,248,35,32,252>>,
    SZ = size(MSG),
    meck:expect(bm_db, insert, fun(addr,L) when length(L) /= 13 ->
                                       error(unexpected_addr_length);
                                  (addr, _) ->
                                       ok
                               end),
    bm_reciever:analyse_packet(<<"addr",
                                 0:(12 - 4)/unit:8>>,
                               SZ,
                               MSG,
                               #state{}),
    ?assert(meck:called(bm_db, insert, '_')).

inv_packet() ->  % {{{2
    [].

inv_packet(_Config) ->  % {{{2
    {ok, MSG} = file:read_file("../../test/data/inv.bin"),
    SZ = size(MSG),
    meck:expect(bm_db, lookup, fun(inventory, I) ->
                                       io:format("~p~n", [I]),
                                       [ok]
                            end),
    bm_reciever:analyse_packet(<<"inv", 0:(12 - 3)/unit:8>>, SZ, MSG, #state{}),
    ?assertEqual(12097, meck:num_calls(bm_db, lookup, [inventory, '_'])),
    ?assert(meck:called(test, send, '_')).

getdata_packet() ->  % {{{2
    [].

getdata_packet(_Config) ->  % {{{2
    {ok, MSG} = file:read_file("../../test/data/getdata.bin"),
    SZ = size(MSG),
    meck:expect(bm_db, lookup, fun(inventory, I) ->
                                       io:format("~p~n", [I]),
                                       [ok]
                            end),
    meck:expect(bm_reciever, create_obj, fun(_) ->
                                                 <<"TEST_MSG">>
                                         end),
    bm_reciever:analyse_packet(<<"getdata", 0:(12 - 7)/unit:8>>, SZ, MSG, #state{}),
    ?assertEqual(1, meck:num_calls(bm_reciever,
                                   create_obj,
                                   [<<165,40,135,49,43,249,18,255,
                                     174,139,155,56,33,113,234,
                                     186,244,19,94,208,251,208,
                                     84,75,224,222,99,93,143,239,
                                     10,190>>])),
    ?assertEqual(1, meck:num_calls(test, 
                                   send,
                                   ['_', <<"TEST_MSG">>])).

object_packet_test() ->  % {{{2
    [].

object_packet_test(_Config) ->  % {{{2
    Data = crypto:rand_bytes(256),
    meck:expect(bm_pow, make_pow, fun(Test) ->
                                          <<2048:64/big-integer, Test/bytes>>
                                  end),
    meck:expect(bm_pow, check_pow, fun(<<2048:64/big-integer, _Test/bytes>>) ->
                                          true
                                  end),
    MSG = bm_message_creator:create_obj(0, 1, 1, Data),
    meck:expect(bm_reciever,
                analyse_object,
                fun(0, 1, _Time, Inv, D, S) when D == Data ->
                        #state{};
                   (Type, Version, Time, Inv, D, S) ->
                        io:format("Wrong call of analyse_object: ~p ~p ~p ~p ~p~n",
                                  [Type, Version, Time, Inv, D]),
                        #state{}
                end),
    bm_reciever:analyse_packet(<<"object">>, size(MSG), MSG, #state{}),
    ?assert(meck:called(bm_reciever, analyse_object, [0, 1, '_', '_', Data, #state{}])),
    ?assert(meck:called(bm_pow, make_pow, '_')),
    ?assert(meck:called(bm_pow, check_pow, '_')).
