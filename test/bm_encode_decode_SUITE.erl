-module(bm_encode_decode_SUITE).

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
         encode_decode_test/1,
         broadcast_encode_decode_test/0,
         broadcast_encode_decode_test/1
        ]).

-include_lib("common_test/include/ct.hrl").
-include("../include/bm.hrl").

%%%===================================================================
%%% Common Test callbacks  % {{{1
%%%===================================================================

all() ->  % {{{2
    [
     encode_decode_test,
     broadcast_encode_decode_test
    ].

suite() ->  % {{{2
    [{timetrap, {seconds, 1600}}].

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
    mnesia:start(),
    {atomic, ok} = mnesia:create_table(inventory,
                                       [
                                        {attributes, record_info(fields, inventory)},
                                        {type, set}]),
    {atomic, ok} = mnesia:create_table(pubkey,
                                       [
                                        {attributes, record_info(fields, pubkey)},
                                        {type, set}]),
    {atomic, ok} = mnesia:create_table(privkey,
                                       [
                                        {attributes, record_info(fields, privkey)},
                                        {type, set}]),
    {atomic, ok} = mnesia:create_table(addr,
                                       [
                                        {attributes,
                                         record_info(fields, network_address)},
                                        {type, set},
                                        {record_name, network_address}]),
    {atomic, ok} = mnesia:create_table(message,
                                       [
                                        {attributes, record_info(fields, message)},
                                        {type, set}
                                        ]),

    bm_db:start_link(),
    PrivKey={privkey,
             <<87,80,73,58,203,124,116,75,140,153,145,217,181,199,85,141,249,51,181>>,
     true,
     make_ref(),
     <<"BM-2D8uEB6d5KVrm3TZYMmLBS63RE6CTzZiRu">>,
     <<110,162,71,114,180,200,139,164,148,156,8,203,145,72,149,132,40,15,
       86,62,210,128,171,97,254,17,46,204,103,161,20,142>>,
     <<234,172,119,60,201,241,191,178,19,125,23,77,105,202,22,16,203,98,
       136,67,77,160,38,42,137,62,54,132,232,83,231,145>>,
     1413446594,
     <<156,164,82,250,230,83,198,254,81,224,238,190,109,53,136,180,15,70,
       174,104,32,210,67,20,106,97,240,47,127,102,206,186,52,44,121,27,86,
       84,65,114,49,178,230,163,30,90,66,147,16,180,250,8,87,208,102,52,
       186,53,255,157,26,144,237,31,52,151,243,8,150,18,116,15,29,175,229,
       199,26,157,195,242,80,118,233,214,48,34,233,216,242,255,66,31,96,
       150,160,96,91,164,135,152,253,29,219,139,66,127,204,133,150,91,37,
       36,239,206,203,192,107,196,7,112,117,140,47,232,12,201,156,138>>},
    #privkey{hash=RIPE,
             public=Pub,
             address=Addr} = PrivKey,
    bm_db:insert(privkey, [PrivKey]),
    <<PSK:64/bytes, PEK:64/bytes>> = Pub,
    Ripe = bm_auth:generate_ripe(binary_to_list(<<4, PSK/bytes, 4, PEK/bits>>)),
    PubKey = #pubkey{
                hash=Ripe,
                pek=PEK,
                psk=PSK
               },
    bm_db:insert(pubkey, 
                 [PubKey]),
    meck:new(bm_dispatcher, [passthrough]),
    bm_decryptor_sup:start_link(),
    bm_dispatcher:start_link(),
    bm_encryptor_sup:start_link(),
    meck:new(bm_pow),
    meck:expect(bm_pow, make_pow, fun(Payload) ->
                                          <<1024:64/big-integer, Payload/bytes>>
                                  end),
    meck:expect(bm_pow, check_pow, fun(<<POW:64/big-integer, _/bytes>>) ->
                                          POW == 1024
                                  end),
    meck:new(bm_sender, [no_link]),
    meck:new(test, [non_strict]),
    bm_dispatcher:register_receiver(test),
    Config.

end_per_testcase(_TestCase, _Config) ->  % {{{2
    meck:unload(),
    mnesia:stop(),
    ok.

%%%===================================================================
%%% Test cases  % {{{1
%%%===================================================================

encode_decode_test() ->  % {{{2
    [].

encode_decode_test(_Config) ->  % {{{2
    [#privkey{hash=RIPE,
              public=Pub,
              address=Addr}] =
    bm_db:lookup(privkey, bm_db:first(privkey)),
    meck:expect(test,
                received,
                fun(Hash) ->
                        {ok,
                         #message{hash = Hash,
                                  to=Addr,
                                  from=Addr,
                                  subject = <<"Test">>,
                                  enc=2,
                                  text = <<"Just test text">>,
                                  status=unread,
                                  folder=incoming,
                                  type=?MSG
                                  }} = bitmessage:get_message(Hash)
                end),
    meck:expect(test,
                sent,
                fun(Hash) ->
                        mnesia:clear_table(message),
                        [#inventory{
                            payload = <<1024:64/big-integer,
                                      _:64/big-integer,
                                      ?MSG:32/big-integer,
                                      1:8/integer,
                                      1:8/integer,
                                      Payload/bytes>>
                           }] = bm_db:lookup(inventory, Hash),
                        bm_message_decryptor:decrypt(Payload, Hash)
                end),
    meck:expect(bm_sender,
                send_broadcast,
                fun(_) ->
                        ok 
                end),
    bitmessage:send_message(Addr,
                            Addr,
                            <<"Test">>,
                            <<"Just test text">>),

    meck:wait(bm_pow, make_pow, '_', 1600),
    meck:wait(bm_sender, send_broadcast, '_', 1600),
    meck:wait(test, received, '_', 1600).

broadcast_encode_decode_test() ->  % {{{2
    [].

broadcast_encode_decode_test(_Config) ->  % {{{2
    [#privkey{hash=RIPE,
              public=Pub,
              address=Addr}] =
    bm_db:lookup(privkey, bm_db:first(privkey)),
    meck:expect(test,
                received,
                fun(Hash) ->
                        {ok,
                         #message{hash = Hash,
                                  to=Addr,
                                  from=Addr,
                                  subject = <<"Test">>,
                                  enc=2,
                                  text = <<"Just test text">>,
                                  status=unread,
                                  folder=incoming,
                                  type=?BROADCAST
                                  }} = bitmessage:get_message(Hash)

                end),
    meck:expect(test,
                sent,
                fun(Hash) ->
                        mnesia:clear_table(message),
                        [#inventory{
                            type=?BROADCAST,
                            payload = <<1024:64/big-integer,
                                      _:64/big-integer,
                                      ?BROADCAST:32/big-integer,
                                      5:8/integer, % Version
                                      1:8/integer, % Stream
                                      _Tag:32/bytes,
                                      Payload/bytes>>
                           }] = bm_db:lookup(inventory, Hash),
                        bm_message_decryptor:decrypt(Payload, Hash)
                end),
    meck:expect(bm_sender,
                send_broadcast,
                fun(_) ->
                        ok 
                end),
    bitmessage:subscribe_broadcast(<<"BM-2D8uEB6d5KVrm3TZYMmLBS63RE6CTzZiRu">>),
    bitmessage:send_broadcast(Addr,
                            <<"Test">>,
                            <<"Just test text">>,
                            2),

    meck:wait(bm_pow, make_pow, '_', 1600),
    meck:wait(bm_sender, send_broadcast, '_', 1600),
    meck:wait(test, received, '_', 1600).
