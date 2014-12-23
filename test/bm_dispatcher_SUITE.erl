-module(bm_dispatcher_SUITE).

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
         message_arrived/0,
         message_arrived/1,
         message_arrived_old/0,
         message_arrived_old/1
        ]).

-include_lib("common_test/include/ct.hrl").
-include("../include/bm.hrl").

%%%===================================================================
%%% Common Test callbacks
%%%===================================================================

all() ->
    [
     message_arrived_old,
     message_arrived
    ].

suite() ->
    [{timetrap, {seconds, 300}}].

groups() ->
    [].

init_per_suite(Config) ->
    application:start(crypto),
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
    meck:new(bm_db, [non_strict]),
    meck:expect(bm_db, wait_db, fun() -> ok end),
    meck:expect(bm_db, select, fun(message, _, _) -> [] end),
    meck:expect(bm_db, insert, fun(_, [PK]) -> io:format("~p~n", [PK])  end),
    meck:expect(bm_db, received, fun(_) -> ok end),
    meck:new(bm_message_creator),
    meck:expect(bm_message_creator, create_ack, fun(_) -> <<"ACK">> end),
    meck:new(bm_sender),
    meck:expect(bm_sender, send_broadcast, fun(Data) -> io:format("send_broadcast(~p)~n", [Data]) end),
    bm_dispatcher:start_link(),
    bm_dispatcher:register_receiver(bm_db),
    Config.

end_per_testcase(_TestCase, _Config) ->
    meck:unload(),
    ok.

%%%===================================================================
%%% Test cases
%%%===================================================================

message_arrived() ->  % {{{1
    [].

message_arrived(_Config) ->  % {{{1
    {ok, MSG} = file:read_file("../../test/data/msg_decr.bin"),
    PubKey = #pubkey{hash= <<0,52,194,59,172,85,148,9,190,117,190,
                             61,197,187,205,66,191,180,14,132>>,
                     pek= <<153,255,234,237,140,242,118,120,64,210,197,
                            12,77,219,35,56,119,191,151,138,16,12,79,8,
                            160,92,57,48,223,66,74,97,223,12,49,131,223,53,
                            236,108,214,169,150,90,115,163,195,246,6,11,16,
                            15,253,99,74,185,80,207,35,105,69,174,232,152>>,
                     psk= <<27,216,141,78,224,205,94,40,84,186,230,248,57,143,207,4,128,121,45,
                            69,207,198,62,218,93,16,179,240,75,89,252,149,85,213,170,33,118,26,
                            17,40,119,74,1,49,247,98,135,2,157,111,108,110,152,180,125,182,143,
                            70,252,149,248,109,88,217>>,
                     time='_'
                    },
    MR = #message{hash= <<"TEST">>, 
                  enc=2, 
                  to= <<"BM-2D8uEB6d5KVrm3TZYMmLBS63RE6CTzZiRu">>, 
                  from= <<"BM-2D8BqFxh5SpfRxnKw5Kg9Kj7HqTdYxkRHu">>, 
                  subject= <<"test">>,
                  folder=incoming,
                  type=msg,
                  ackdata= <<233,190,180,217,111,98,106,101,99,116,
                             0,0,0,0,0,0,0,0,0,54,178,40,94,40,
                             0,0,0,0,0,139,159,97,0,0,0,0,84,123,152,152,
                             0,0,0,2,1,1,204,189,227,150,224,152,112,109,
                             222,102,107,173,118,220,3,185,20,71,103,
                             122,21,177,95,185,161,197,215,61,57,250,238,20>>,
                  status=unread,
                  text= <<"15">>,
                 time='_'},
    meck:expect(bm_db,
                lookup,
                fun(inventory,
                    <<"TEST">>) ->
                        {ok, EMSG} = file:read_file("../../test/data/msg_encr.bin"),
                        [#inventory{payload=EMSG}]
                end),
    bm_dispatcher:message_arrived(
      MSG,
      <<"TEST">>, 
      <<"BM-2D8uEB6d5KVrm3TZYMmLBS63RE6CTzZiRu">>),
    io:format("Function called~n"),
    meck:wait(bm_db,
              insert,
              [pubkey, [PubKey]],
              10000),
    io:format("Pubkey inserted~n"),
    meck:wait(bm_db,
              insert,
              [message, [MR]],
              10000),
    io:format("Message inserted~n"),
    meck:wait(bm_message_creator,
              create_ack,
              [MR],
              10000),
    io:format("Ack created~n"),
    meck:wait(bm_sender,
              send_broadcast,
              [<<"ACK">>],
              10000),
    io:format("Ack sent~n"),
    io:format("Done").

message_arrived_old() ->  %{{{1
    [].

message_arrived_old(_Config) ->  %{{{1
    PubKey = #pubkey{hash= <<0,49,231,251,176,243,69,133,204,71,175,27,126,246,144,203,152,238,240,119>>,
                     psk= <<228,178,121,192,222,101,137,85,
                            198,31,83,237,164,114,185,13,93,
                            71,208,48,137,66,145,32,244,170,
                            165,24,196,166,39,198,70,225,78,
                            90,40,26,105,50,4,19,134,177,46,
                            114,71,223,116,72,180,20,36,132,
                            183,26,25,122,214,170,90,217,13,154>>,
                     pek= <<35,167,144,184,234,131,49,225,12,37,5,
                            178,124,33,245,219,227,94,200,237,207,
                            136,118,92,187,198,219,91,184,23,185,
                            247,54,22,118,105,125,143,215,208,95,
                            131,150,215,202,130,41,46,223,225,28,
                            186,255,130,217,4,33,168,184,42,5,32,151,159>>,
                     time='_'
                    },
    MR = #message{hash= <<"TEST">>, 
                  enc=2, 
                  to= <<"BM-2D8uEB6d5KVrm3TZYMmLBS63RE6CTzZiRu">>, 
                  from= <<"BM-2D88R4V4M3QuYMvWkpBrz5Q7sUKLWjZuSt">>, 
                  subject= <<"Test">>,
                  folder=incoming,
                  ackdata= <<233,190,180,217,109,115,103,
                             0,0,0,0,0,0,0,0,0,0,0,0,49,
                             198,3,255,157,0,0,0,0,0,98,
                             197,120,0,0,0,0,84,63,128,74,
                             1,213,157,125,204,59,18,206,
                             143,169,151,59,233,139,121,
                             184,4,19,59,64,97,37,20,254,
                             103,166,97,82,90,60,71,217,208>>,
                  status=unread,
                  type=msg,
                  text= <<"1">>,
                 time='_'},
    bm_dispatcher:message_arrived(
      <<1,4,1,0,0,0,1,228,178,121,192,222,101,137,
        85,198,31,83,237,164,114,185,13,93,71,208,
        48,137,66,145,32,244,170,165,24,196,166,39,
        198,70,225,78,90,40,26,105,50,4,19,134,177,
        46,114,71,223,116,72,180,20,36,132,183,26,
        25,122,214,170,90,217,13,154,35,167,144,184,
        234,131,49,225,12,37,5,178,124,33,245,219,
        227,94,200,237,207,136,118,92,187,198,219,
        91,184,23,185,247,54,22,118,105,125,143,215,
        208,95,131,150,215,202,130,41,46,223,225,28,
        186,255,130,217,4,33,168,184,42,5,32,151,
        159,253,1,64,253,54,176,0,87,80,73,58,203,
        124,116,75,140,153,145,217,181,199,85,141,
        249,51,181,2,19,83,117,98,106,101,99,116,58,
        84,101,115,116,10,66,111,100,121,58,49,73,
        233,190,180,217,109,115,103,0,0,0,0,0,0,0,0,
        0,0,0,0,49,198,3,255,157,0,0,0,0,0,98,197,
        120,0,0,0,0,84,63,128,74,1,213,157,125,204,
        59,18,206,143,169,151,59,233,139,121,184,4,
        19,59,64,97,37,20,254,103,166,97,82,90,60,
        71,217,208,70,48,68,2,32,48,0,162,49,197,
        118,100,9,224,220,193,148,249,90,41,232,120,
        67,187,196,87,192,144,164,172,158,253,23,
        110,118,4,198,2,32,101,164,233,117,20,241,
        193,247,115,177,218,4,224,185,12,172,218,
        161,239,237,87,55,239,112,184,120,198,56,
        185,217,151,83,9,9,9,9,9,9,9,9,9>>,
       <<"TEST">>, 
       <<"BM-2D8uEB6d5KVrm3TZYMmLBS63RE6CTzZiRu">>),
    io:format("Function called~n"),
    meck:wait(bm_db,
              insert,
              [pubkey, [PubKey]],
              1000),
    io:format("Pubkey inserted~n"),
    meck:wait(bm_db,
              insert,
              [message, [MR]],
              1000),
    io:format("Message inserted~n"),
    meck:wait(bm_message_creator,
              create_ack,
              [MR],
              1000),
    io:format("Ack created~n"),
    meck:wait(bm_sender,
              send_broadcast,
              [<<"ACK">>],
              1000),
    io:format("Ack sent~n"),
    io:format("Done").
