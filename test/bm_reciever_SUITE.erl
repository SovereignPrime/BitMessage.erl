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
        inv_packet/1
        %getdata_packet/0,
        %getdata_packet/1,
        %get_pubkey_packet/0,
        %get_pubkey_packet/1,
        %pubkey_packet/0,
        %pubkey_packet/1,
        %msg_packet/0,
        %msg_packet/1,
        %broadcast_packet/0,
        %broadcast_packet/1
    ]).
%% }}}

%%%===================================================================
%%% Common Test callbacks
%%%===================================================================

all() ->  % {{{1
    [
     version_packet,
     verack_packet,
     addr_packet,
     inv_packet
    ].

suite() ->  % {{{1
    [{timestamp, {seconds, 30}}].

groups() ->  % {{{1
    [].

init_per_suite(Config) ->  % {{{1
    Config.

end_per_suite(Config) ->  % {{{1
    ok.

group(_GroupName) ->  % {{{1
    [].

init_per_group(_GroupName, Config) ->  % {{{1
    Config.

end_per_group(_GroupName, _Config) ->  % {{{1
    ok.

init_per_testcase(_TestCase, Config) ->  % {{{1
    {ok, OSocket} = gen_tcp:listen(0, []),
    {ok, Port} = inet:port(OSocket),
    {ok, Socket} = gen_tcp:connect({127, 0, 0, 1}, Port, [inet, {keepalive, true}]),
    meck:new(test, [non_strict]),
    meck:expect(test, send, fun(Socket, MSG) ->
                                    io:format("~p~n", [MSG])
                            end),
    meck:new(bm_db),
    meck:expect(bm_db, insert, fun(addr,L) when length(L) /= 13 ->
                                       error(unexpected_addr_length);
                                  (addr, _) ->
                                       ok
                            end),
    meck:expect(bm_db, lookup, fun(inventory, I) ->
                                       ok
                            end),
    [{osocket, OSocket}, {socket, Socket} | Config].

end_per_testcase(_TestCase, Config) ->  % {{{1
    Socket = dict:fetch(socket, dict:from_list(Config)),
    gen_udp:close(Socket),
    ok.

%%%===================================================================
%%% Test cases
%%%===================================================================
version_packet() ->  % {{{1
    [].

version_packet(Config) ->  % {{{1
    Socket = dict:fetch(socket, dict:from_list(Config)),
    MSG = <<0,0,0,2,0,0,0,0,0,0,0,1,0,0,0,0,84,71,44,79,0,0,0,0,0,0,0,1,0,0,0,0,
            0,0,0,0,0,0,255,255,94,50,253,51,201,131,0,0,0,0,0,0,0,1,0,0,0,0,0,
            0,0,0,0,0,255,255,127,0,0,1,32,252,115,170,57,172,72,126,34,107,20,
            47,80,121,66,105,116,109,101,115,115,97,103,101,58,48,46,52,46,50,
            47,1,1>>,
    #state{version=2,
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

verack_packet() ->  % {{{1
    [].

verack_packet(_Config) ->  % {{{1
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

addr_packet() ->  % {{{1
    [].

addr_packet(_Config) ->  % {{{1
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
    bm_reciever:analyse_packet(<<"addr",
                                 0:(12 - 4)/unit:8>>,
                               SZ,
                               MSG,
                               #state{}),
    ?assert(meck:validate(bm_db)).

inv_packet() ->  % {{{1
    [].

inv_packet(_Config) ->  % {{{1
    {ok, MSG} = file:read_file("../../test/data/inv.bin"),
    SZ = size(MSG),
    bm_reciever:analyse_packet(<<"inv", 0:(12 - 3)/unit:8>>, SZ, MSG, #state{}),
    ?assertEqual(12097, meck:num_calls(bm_db, lookup, [inventory, '_'])),
    ?assert(meck:validate(test)).

% getdata_packet() ->  % {{{1
%     [].
%
% getdata_packet(_Config) ->  % {{{1
% 
%     SZ = size(MSG),
%     bm_reciever:analyse_packet(<<"getdata", 0:(12 - 7)/unit:8>>, SZ, MSG, #state{}).
%
% get_pubkey_packet() ->  % {{{1
%     [].
%
% get_pubkey_packet(_Config) ->  % {{{1
% 
%     SZ = size(MSG),
%     bm_reciever:analyse_packet(<<"getpubkey", 0:(12 - 9)/unit:8>>, SZ, MSG, #state{}).
% pubkey_packet() ->  % {{{1
%     [].
%
% pubkey_packet(_Config) ->  % {{{1
% 
%     SZ = size(MSG),
%     bm_reciever:analyse_packet(<<"pubkey", 0:(12 - 6)/unit:8>>, SZ, MSG, #state{}).
% 
% msg_packet() ->  % {{{1
%     [].
% 
% msg_packet(_Config) ->  % {{{1
% 
%     SZ = size(MSG),
%     bm_reciever:analyse_packet(<<"msg", 0:(12 - 3)/unit:8>>, SZ, MSG, #state{}).
%
% broadcast_packet() ->  % {{{1
%     [].
%
% broadcast_packet(_Config) ->  % {{{1
% 
%     SZ = size(MSG),
%     bm_reciever:analyse_packet(<<"broadcast", 0:(12 - 9)/unit:8>>, SZ, MSG, #state{}).
