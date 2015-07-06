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
    {atomic, ok} = mnesia:create_table(bm_file,
                                       [
                                        {attributes, record_info(fields, bm_file)},
                                        {type, set}
                                        ]),
    {atomic, ok} = mnesia:create_table(bm_filechunk,
                                       [
                                        {attributes, record_info(fields, bm_filechunk)},
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
    ToPrK = {privkey,<<210,194,106,100,108,26,193,16,182,201,15,226,233,229,239,11,107,167,
                       67>>,
             true,
             make_ref(),
             <<"BM-2DBT7LiWBzkVYyrQBAgarC7k9AKuVVLJKx">>,
             <<24,185,35,75,216,144,25,197,74,139,212,234,22,68,135,150,95,184,6,
               139,161,141,88,182,226,116,200,181,24,193,241,55>>,
             <<12,242,104,59,184,38,44,35,34,121,98,233,248,93,13,99,157,49,40,159,
               4,42,216,113,82,50,112,91,3,205,206,163>>,
             1433418078,
             <<139,38,228,167,85,121,158,224,73,47,254,28,30,147,69,15,92,159,177,
               52,97,164,177,70,48,122,23,119,115,18,122,145,220,149,125,245,123,
               175,73,251,108,80,175,14,226,233,92,61,107,104,106,189,136,12,112,
               143,238,122,209,248,131,137,46,130,157,143,211,245,169,7,26,96,233,
               81,180,49,165,176,107,184,112,92,113,0,17,47,98,223,190,165,77,96,
               168,157,97,129,1,192,196,201,61,117,8,150,19,169,151,110,129,224,
               224,204,141,139,120,61,109,210,44,179,123,232,176,7,156,207,216,251>>},
    bm_db:insert(privkey, [PrivKey]),
    bm_db:insert(privkey, [ToPrK]),
    <<PSK:64/bytes, PEK:64/bytes>> = Pub,
    Ripe = bm_auth:generate_ripe(binary_to_list(<<4, PSK/bytes, 4, PEK/bits>>)),
    PubKey = #pubkey{
                hash=Ripe,
                pek=PEK,
                psk=PSK
               },
    bm_db:insert(pubkey, 
                 [PubKey]),
    bm_decryptor_sup:start_link(),
    meck:new(test, [non_strict]),
    application:set_env(bitmessage, receiver, test),
    bitmessage:start_link(),
    bm_encryptor_sup:start_link(),
    meck:new(bm_pow),
    meck:expect(bm_pow, make_pow, fun(Payload) ->
                                          <<1024:64/big-integer, Payload/bytes>>
                                  end),
    meck:expect(bm_pow, check_pow, fun(<<POW:64/big-integer, _/bytes>>) ->
                                          POW == 1024
                                  end),
    meck:new(bm_sender, [no_link]),
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
              address=Addr}=PK] =
    bm_db:lookup(privkey, bm_db:first(privkey)),

    To = <<"BM-2DBT7LiWBzkVYyrQBAgarC7k9AKuVVLJKx">>,
    meck:expect(test,
                received,
                fun(Hash) ->
                        {ok,
                         #message{hash = Hash,
                                  to=Addr,
                                  from=To,
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
                            payload=Payload
                           }] = bm_db:lookup(inventory, Hash),
                        mnesia:clear_table(inventory),
                        bm_decryptor:process_object(Payload)
                end),
    meck:expect(bm_sender,
                send_broadcast,
                fun(_) ->
                        ok 
                end),
    bitmessage:send_message(To, 
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
              address=Addr} = PK] =
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
                            payload=Payload
                           }] = bm_db:lookup(inventory, Hash),
                        mnesia:clear_table(inventory),
                        bm_decryptor:process_object(Payload)
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
