-module(bm_file_SUITE).
-include("../include/bm.hrl").

%% Common Test callbacks
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
         test_attachment_encode_decode/0,
         test_attachment_encode_decode/1,
         test_filechunk_query/0,
         test_filechunk_query/1,
         test_filechunk_send/0,
         test_filechunk_send/1
        ]).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Common Test callbacks  % {{{1
%%%===================================================================

all() ->  % {{{2
    [
     test_attachment_encode_decode,
     test_filechunk_query,
     test_filechunk_send
    ].

suite() ->  % {{{2
    [{timetrap, {minutes, 30}}].

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
    mnesia:create_schema([node()]),
    mnesia:start(),
    {atomic, ok} = mnesia:create_table(inventory,
                                       [
                                        {attributes, record_info(fields, inventory)},
                                        {type, set}]),
    {atomic, ok} = mnesia:create_table(inventory_tmp,
                                       [
                                        {attributes, record_info(fields, inventory)},
                                        {type, set},
                                        {record_name, inventory}
                                       ]),
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
                                        {type, set},
                                        {record_name, message}]),
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
    meck:new(timer, [unstick, passthrough]),
    bm_dispatcher:register_receiver(test),
    bm_decryptor:callback(test),
    Config.

end_per_testcase(_TestCase, _Config) ->  % {{{2
    meck:unload(),
    mnesia:stop(),
    mnesia:delete_schema([node()]),
    ok.

%%%===================================================================
%%% Test cases  % {{{1
%%%===================================================================

test_attachment_encode_decode() ->  % {{{2
    [].
test_attachment_encode_decode(_Config) -> % {{{2
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
                                  subject = <<"Test message with file">>,
                                  enc=3,
                                  text = <<"File in attachment">>,
                                  status=unread,
                                  folder=incoming,
                                  type=?MSG
                                  }} = bitmessage:get_message(Hash),
                        Files = mnesia:table_info(bm_file, size),
                        case Files of
                            2 ->
                                ok;
                            FL ->
                                meck:exception(error, iolib:format("Wrong number of attachments received; ~p~n", [FL]))
                        end
                end),
    meck:expect(test,
                sent,
                fun(Hash) ->
                        Files = mnesia:table_info(bm_file, size),
                        case Files of
                            2 ->
                                mnesia:clear_table(bm_file),
                                mnesia:clear_table(message),
                                [#inventory{
                                    payload = Payload
                                   }] = bm_db:lookup(inventory, Hash),
                                mnesia:clear_table(inventory),
                                bm_decryptor:process_object(Payload);
                            FL ->
                                meck:exception(error, iolib:format("Wrong number of attachments sent: ~p~n", [FL]))
                        end
                end),
    meck:expect(bm_sender,
                send_broadcast,
                fun(_) ->
                        ok 
                end),
    bitmessage:send_message(Addr,
                            Addr,
                            <<"Test message with file">>,
                            <<"File in attachment">>,
                            ["../../test/data/file.txt",
                             "../../test/data/file1.txt"]),

    meck:wait(bm_pow, make_pow, '_', 1600),
    meck:wait(bm_sender, send_broadcast, '_', 1600),
    meck:wait(test, received, '_', 1600).

test_filechunk_query() ->  % {{{2
    [].

test_filechunk_query(_Config) -> % {{{2
    bm_attachment_sup:start_link(),
    [#privkey{hash=RIPE,
              public=Pub,
              address=Addr}] =
        bm_db:lookup(privkey, bm_db:first(privkey)),
    meck:expect(test,
                sent,
                fun(Hash) ->
                        {ok,
                        #message{attachments=[Att]}} = bitmessage:get_message(Hash),
                        mnesia:clear_table(bm_filechunk),
                        bitmessage:get_attachment(Att, "../../test/data")
                end),
    meck:expect(test,
                downloaded,
                fun(_) ->
                        ok
                end),
    meck:expect(test,
                filechunk_sent,
                fun(_, _) ->
                        ok
                end),
    meck:expect(bm_sender,
                send_broadcast,
                fun(<<_:25/bytes,
                      Inv:32/bytes>>
                      ) ->
                        case bm_db:lookup(inventory, Inv) of
                            [#inventory{
                                type=Type,
                                payload = <<_:22/bytes, 
                                            FileHash:64/bytes,
                                            ChunkHash:64/bytes>>
                               } = Inventory]  when Type == ?GETFILECHUNK -> 
                                bm_attachment_srv:send_chunk(FileHash,
                                                             ChunkHash,
                                                             test),
                                bm_attachment_srv:received_chunk(FileHash, ChunkHash);
                            [I] ->
                                Size = mnesia:table_info(bm_filechunk, size),
                                ok
                        end;
                   (B) ->
                        error_logger:info_msg("Size: ~p~n", [size(B)])
                end),


    bitmessage:send_message(Addr,
                            Addr,
                            <<"Test message with file">>,
                            <<"File in attachment">>,
                            ["../../test/data/rand64k.raw"]),
    meck:wait(bm_pow, make_pow, '_', 16000),
    meck:wait(bm_sender, send_broadcast, '_', 16000),
    meck:wait(test, downloaded, '_', 1600000),
    ?assertEqual(65, mnesia:table_info(bm_filechunk, size)),
    ?assertEqual(131, meck:num_calls(bm_sender, send_broadcast, '_')),
    ?assertEqual(65, meck:num_calls(test, filechunk_sent, '_')),
    ?assert(meck:called(test, downloaded, '_')).

test_filechunk_send() ->  % {{{2
    [].

test_filechunk_send(_Config) -> % {{{2
    bm_attachment_sup:start_link(),
    {Pub, Priv} = Keys = crypto:generate_key(ecdh, secp256k1),
    File = #bm_file{
              hash = <<236,232,252,93,50,80,86,138,161,48,73,206,49,121,115,
                       145,35,159,150,21,169,198,231,167,229,103,36,26,243,
                       163,102,54,24,115,165,10,106,202,230,103,120,78,56,35,
                       102,66,187,183,129,128,131,36,144,181,100,109,251,41,
                       37,171,111,21,73,199>>,
              name= "file.txt",
              size=90,
              path="../../test/data",
              chunks=[<<24,157,228,172,234,149,216,48,114,205,82,28,220,
                        91,122,175,32,204,135,55,206,74,204,174,13,144,
                        55,80,144,113,94,149,198,114,48,173,79,104,214,
                        110,99,205,53,69,173,238,184,247,151,138,3,162,
                        93,168,49,197,126,17,218,51,26,255,211,238>>],
              key=Keys,
              time=bm_types:timestamp()
             },
    FileChunk = #bm_filechunk{
                   hash = <<24,157,228,172,234,149,216,48,114,205,82,28,220,
                            91,122,175,32,204,135,55,206,74,204,174,13,144,
                            55,80,144,113,94,149,198,114,48,173,79,104,214,
                            110,99,205,53,69,173,238,184,247,151,138,3,162,
                            93,168,49,197,126,17,218,51,26,255,211,238>>,
                   size = 1024,
                   file = <<236,232,252,93,50,80,86,138,161,48,73,206,49,121,115,
                            145,35,159,150,21,169,198,231,167,229,103,36,26,243,
                            163,102,54,24,115,165,10,106,202,230,103,120,78,56,35,
                            102,66,187,183,129,128,131,36,144,181,100,109,251,41,
                            37,171,111,21,73,199>>,
                   data = <<31,139,8,0,0,0,0,0,0,3,237,210,193,78,195,48,
                            12,128,225,158,247,20,126,0,148,58,105,201,
                            158,129,243,246,2,17,77,213,138,106,67,137,39,216,
                            219,19,224,10,183,9,16,250,191,139,21,219,
                            146,109,41,206,245,206,245,150,171,245,83,178,
                            212,207,235,150,157,189,90,119,67,234,85,227,
                            56,118,170,234,247,247,250,30,213,127,190,63,248,
                            33,116,62,140,49,68,191,31,52,180,254,160,131,
                            118,162,183,92,226,59,151,106,169,180,85,
                            126,98,214,31,116,92,243,36,47,171,45,146,182,77,
                            108,89,171,204,231,34,165,125,136,249,210,50,83,
                            78,173,246,32,143,229,234,156,219,201,23,14,75,
                            122,202,245,57,167,146,239,164,158,79,167,108,18,
                            227,238,183,47,3,0,0,0,0,0,0,0,0,0,0,0,0,128,255,
                            237,13,54,140,167,14,0,40,0,0>>,
                   _ = '_'
                  },
    meck:expect(bm_sender,
                send_broadcast,
                fun(<<_:25/bytes,
                      Hash/bytes>>) ->
                        [#inventory{
                            payload = Payload
                           }] = bm_db:lookup(inventory, Hash),
                        mnesia:clear_table(inventory),
                        bm_decryptor:process_object(Payload)
                end),
    meck:expect(test,
                filechunk_sent,
                fun(FileHash, ChunkHash) 
                      when FileHash == File#bm_file.hash,
                           ChunkHash == FileChunk#bm_filechunk.hash->
                        case bm_db:lookup(bm_filechunk, ChunkHash) of
                            [] ->
                                meck:exception(error, "No chunk in DB");
                            [FC] ->
                                mnesia:clear_table(bm_filechunk),
                                mnesia:dirty_write(bm_filechunk,
                                                   FC#bm_filechunk{data=undefined}),
                                ok
                        end
                end),
    meck:expect(test,
                filechunk_received,
                fun(FileHash, ChunkHash) ->
                        ok
                end),
    bm_db:insert(bm_file, [File]),
    bm_decryptor_sup:add_decryptor(#privkey{pek=Priv}),
    bm_attachment_srv:send_chunk(File#bm_file.hash,
                                 FileChunk#bm_filechunk.hash,
                                test),
    meck:wait(bm_pow, make_pow, '_', 1600),
    meck:wait(bm_sender, send_broadcast, '_', 1600),
    meck:wait(test, filechunk_sent, '_', 1600),
    meck:wait(test, filechunk_received, '_', 1600).
