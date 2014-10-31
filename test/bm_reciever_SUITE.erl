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
        get_pubkey_packet/0,
        get_pubkey_packet/1,
        pubkey_packet/0,
        pubkey_packet/1,
        msg_packet/0,
        msg_packet/1,
        broadcast_packet/0,
        broadcast_packet/1
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
     get_pubkey_packet,
     pubkey_packet,
     msg_packet,
     broadcast_packet
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
    meck:expect(bm_sender, send_broadcast, fun(_) ->
                                                   ok
                                                end),
    Config.

end_per_testcase(_TestCase, Config) ->  % {{{2
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
    meck:expect(bm_message_creator, create_obj, fun(_) ->
                                                        <<"TEST_MSG">>
                                                end),
    bm_reciever:analyse_packet(<<"getdata", 0:(12 - 7)/unit:8>>, SZ, MSG, #state{}),
    ?assertEqual(1, meck:num_calls(bm_message_creator,
                                   create_obj,
                                   [<<165,40,135,49,43,249,18,255,
                                     174,139,155,56,33,113,234,
                                     186,244,19,94,208,251,208,
                                     84,75,224,222,99,93,143,239,
                                     10,190>>])),
    ?assertEqual(1, meck:num_calls(test, 
                                   send,
                                   ['_', <<"TEST_MSG">>])).

get_pubkey_packet() ->  % {{{2
    [].

get_pubkey_packet(_Config) ->  % {{{2
    {ok, MSG} = file:read_file("../../test/data/getpubkey.bin"),
    SZ = size(MSG),
    meck:expect(bm_types, timestamp, fun() ->
                                             1414575390
                                     end),
    bm_reciever:analyse_packet(<<"getpubkey", 0:(12 - 9)/unit:8>>, SZ, MSG, #state{}),
    ?assert(meck:called(bm_db, 
                        lookup,
                        [inventory, <<61,23,11,37,175,120,225,39,187,
                                      70,65,167,37,17,50,92,251,119,
                                      0,229,90,19,107,165,70,62,213,
                                      187,254,82,96,24>>])),
    ?assert(meck:called(bm_db, 
                        insert,
                        [inventory,
                         [#inventory{
                             hash= <<61,23,11,37,175,120,225,39,187,
                                     70,65,167,37,17,50,92,251,119,
                                     0,229,90,19,107,165,70,62,213,
                                     187,254,82,96,24>>,
                             payload=MSG,
                             type= <<"getpubkey">>,
                             stream=1,
                             _='_'} ]])),
    ?assert(meck:called(bm_message_creator, create_inv, '_')),
    ?assert(meck:called(bm_sender, send_broadcast, '_')).

pubkey_packet() ->  % {{{2
    [].

pubkey_packet(_Config) ->  % {{{2
    {ok, MSG} = file:read_file("../../test/data/pubkey.bin"),
    SZ = size(MSG),
    meck:expect(bm_types, timestamp, fun() ->
                                             1414575390
                                     end),
    meck:expect(bm_db, insert, fun(_, _) ->
                                       ok
                            end),
    meck:expect(bm_message_encryptor, pubkey, fun(_) ->
                                                      ok
                                              end),
    bm_reciever:analyse_packet(<<"pubkey", 0:(12 - 6)/unit:8>>, SZ, MSG, #state{}),
    PK = #pubkey{  % {{{2
            hash= <<220,34,200,174,75,196,14,17,9,238,
                    32,37,187,145,7,187,115,123,61,153>>,
            data= <<19,216,241,0,0,0,0,0,0,0,0,0,84,79, % {{{3
                    215,230,4,1,80,5,121,62,120,184,
                    102,24,179,133,127,118,44,51,150,
                    172,24,158,192,38,134,228,16,181,
                    147,161,213,69,92,98,237,233,105,
                    114,218,231,196,58,18,154,234,119,
                    238,208,148,94,55,13,2,202,0,32,90,
                    135,221,171,67,137,65,158,120,194,
                    203,232,238,153,202,132,192,206,81,
                    197,39,95,202,196,43,51,215,229,
                    202,232,66,149,0,32,209,35,173,221,
                    136,82,114,180,95,94,56,122,228,
                    219,114,140,56,32,202,149,76,164,
                    23,52,206,73,156,177,45,233,49,100,
                    0,36,222,118,144,167,211,164,221,
                    117,167,232,139,195,22,12,69,182,
                    251,208,227,107,171,75,182,29,201,
                    52,166,177,239,116,192,84,160,194,
                    239,187,80,85,103,80,196,67,107,143,
                    104,62,186,187,60,55,46,38,9,242,
                    89,115,244,74,222,131,205,83,173,
                    181,184,188,92,94,16,225,16,246,173,
                    193,33,48,174,86,41,80,194,71,121,
                    20,95,205,121,197,8,76,151,143,43,
                    252,55,181,240,141,66,213,102,54,
                    223,214,64,234,214,116,181,18,110,
                    230,173,92,140,148,73,202,154,225,
                    110,59,238,251,145,133,127,198,19,
                    160,138,134,255,59,147,123,172,51,
                    179,210,189,255,253,232,167,70,66,
                    233,58,154,169,224,193,56,143,249,
                    153,171,174,132,78,197,168,125,46,
                    159,116,21,81,44,88,191,140,79,210,
                    10,253,122,121,212,119,34,30,138,
                    58,246,217,228,229,149,123,250,91,
                    5,123,166,155,76,238,226,126,35,
                    168,220,60,230,220,148,118,183,28,
                    103,2,9,41,24,157,157,211,244,228,
                    171,114,73,129,132,217,203,49,164,
                    51,69,212,35,213,96,67,207,177,51,
                    95,160,232,138,137,215,133,30,224,
                    224,242,97,219,185>>,
            % }}}
            psk= <<120,184,102,24,179,133,127,118,44,51,
                   150,172,24,158,192,38,134,228,
                   16,181,147,161,213,69,92,98,237,233,
                   105,114,218,231,196,58,18,154,
                   234,119,238,208,148,94,55,13,2,202,
                   0,32,90,135,221,171,67,137,65,158,
                   120,194,203,232,238,153,202,132>>,
            pek= <<192,206,81,197,39,95,202,196,43,51,
                   215,229,202,232,66,149,0,32,209,
                   35,173,221,136,82,114,180,95,94,56,
                   122,228,219,114,140,56,32,202,149,
                   76,164,23,52,206,73,156,177,45,233,
                   49,100,0,36,222,118,144,167,211,
                   164,221,117,167,232,139,195>>,
            _='_'},  % }}}
    ?assert(meck:called(bm_db, 
                        lookup,
                        [inventory, <<1,24,237,23,227,179,132,217,171,
                                      32,89,140,91,48,42,88,212,154,
                                      207,104,198,101,212,68,49,246,
                                      192,205,88,169,158,12>>])),
    ?assert(meck:called(bm_db, 
                        insert,
                        [inventory,
                         [#inventory{
                             %hash= <<1,24,237,23,227,179,132,217,171,
                             %        32,89,140,91,48,42,88,212,154,
                             %        207,104,198,101,212,68,49,246,
                             %        192,205,88,169,158,12>>,
                             payload=MSG,
                             type= <<"pubkey">>,
                             stream=1,
                             _='_'} ]])),
    ?assert(meck:called(bm_db, insert, [pubkey, [PK]])),
    ?assert(meck:called(bm_message_creator, create_inv, '_')),
    ?assert(meck:called(bm_message_encryptor, pubkey, [PK])),
    ?assert(meck:called(bm_sender, send_broadcast, '_')).

msg_packet() ->  % {{{2
    [].

msg_packet(_Config) ->  % {{{2
    {ok, MSG} = file:read_file("../../test/data/msg.bin"),
    SZ = size(MSG),
    meck:expect(bm_types, timestamp, fun() ->
                                             1414575390
                                     end),
    meck:expect(bm_db, match, fun(_, _) ->
                                       []
                            end),
    meck:expect(bm_message_decryptor,
                decrypt_message,
                fun(_, _) ->
                        ok
                end),
    bm_reciever:analyse_packet(<<"msg", 0:(12 - 3)/unit:8>>, SZ, MSG, #state{}),
    ?assert(meck:called(bm_db, 
                        lookup,
                        [inventory, <<181,49,89,67,9,108,64,192,100,111,153,
                                      153,56,147,229,185,156,48,87,89,235,64,
                                      105,93,44,90,85,247,182,164,192,240>>])),
    ?assert(meck:called(bm_db, 
                        insert,
                        [inventory,
                         [#inventory{
                             %hash= <<181,49,89,67,9,108,64,192,100,111,153,
                             %         153,56,147,229,185,156,48,87,89,235,64,
                             %         105,93,44,90,85,247,182,164,192,240>>,
                             %payload=MSG,
                             type= <<"msg">>,
                             stream=1,
                             _='_'} ]])),
    ?assert(meck:called(bm_message_creator, create_inv, '_')),
    ?assert(meck:called(bm_sender, send_broadcast, '_')),
    ?assert(meck:called(bm_message_decryptor, decrypt_message, '_')).
    

broadcast_packet() ->  % {{{2
    [].

broadcast_packet(_Config) ->  % {{{2
    {ok, MSG} = file:read_file("../../test/data/broadcast.bin"),
    SZ = size(MSG),
    meck:expect(bm_types, timestamp, fun() ->
                                             1414575390
                                     end),
    meck:expect(bm_message_decryptor,
                decrypt_broadcast,
                fun(_, _) ->
                        ok
                end),
    bm_reciever:analyse_packet(<<"broadcast", 0:(12 - 9)/unit:8>>, SZ, MSG, #state{}),
    ?assert(meck:called(bm_db, 
                        lookup,
                        [inventory, <<195,91,41,65,161,132,186,147,163,5,38,21,
                                      67,135,249,10,88,34,210,104,128,69,
                                      237,92,137,78,44,167,138,191,151,170>>])),
    ?assert(meck:called(bm_db, 
                        insert,
                        [inventory,
                         [#inventory{
                             hash= <<195,91,41,65,161,132,186,147,163,5,38,21,
                                     67,135,249,10,88,34,210,104,128,69,
                                     237,92,137,78,44,167,138,191,151,170>>,
                             payload=MSG,
                             type= <<"broadcast">>,
                             stream=1,
                             _='_'} ]])),
    ?assert(meck:called(bm_message_creator, create_inv, '_')),
    ?assert(meck:called(bm_sender, send_broadcast, '_')),
    ?assert(meck:called(bm_message_decryptor, decrypt_broadcast, '_')).

%%====================================================================
%% Packet tests  {{{1
%%====================================================================
