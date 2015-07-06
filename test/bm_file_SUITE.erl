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
     %test_filechunk_query,
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
    #privkey{public=Pub} = PrivKey,
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
    meck:new(test, [non_strict]),
    meck:new(timer, [unstick, passthrough]),
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
    [#privkey{address=Addr}] =
    bm_db:lookup(privkey, bm_db:first(privkey)),
    To = <<"BM-2DBT7LiWBzkVYyrQBAgarC7k9AKuVVLJKx">>,
    meck:expect(test,
                received,
                fun(Hash) ->
                        {ok,
                         #message{hash = Hash,
                                  to=Addr,
                                  from=To,
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
    bitmessage:send_message(To,
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
    [#privkey{address=Addr}] =
    bm_db:lookup(privkey, bm_db:first(privkey)),
    To = <<"BM-2DBT7LiWBzkVYyrQBAgarC7k9AKuVVLJKx">>,
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
                               }]  when Type == ?GETFILECHUNK -> 
                                bm_attachment_srv:send_chunk(FileHash,
                                                             ChunkHash),
                                bm_attachment_srv:received_chunk(FileHash, ChunkHash);
                            [_] ->
                                ok
                        end;
                   (B) ->
                        error_logger:info_msg("Size: ~p~n", [size(B)])
                end),


    bitmessage:send_message(To,
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
    {_Pub, Priv} = Keys = crypto:generate_key(ecdh, secp256k1),
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
                   data = <<31,139,8,0,0,0,0,0,0,3,236,183,99,172,48,81,214,168,
                            121,108,219,182,109,219,182,109,219,182,109,219,231,
                            61,126,143,109,219,182,109,77,247,189,201,252,232,
                            100,230,254,233,233,111,126,244,147,74,237,93,73,37,
                            123,165,106,63,107,173,77,71,71,79,71,71,239,98,234,
                            236,66,111,98,232,98,72,111,235,108,78,103,100,105,7,
                            240,239,132,129,145,129,129,141,133,5,128,129,129,
                            129,145,157,149,225,159,35,3,227,255,126,254,95,83,6,
                            38,118,0,70,38,22,86,22,54,86,22,118,22,166,127,188,
                            207,200,198,194,6,64,192,240,111,141,226,255,1,87,
                            103,23,67,167,127,132,242,159,88,235,255,175,72,112,
                            2,253,115,80,145,171,112,4,36,94,82,106,5,116,223,29,
                            146,65,185,133,152,104,212,98,7,154,0,32,136,247,252,
                            251,226,119,139,189,36,143,202,0,57,30,189,134,232,
                            77,46,38,47,240,135,141,122,199,128,229,203,111,221,
                            68,21,128,0,80,26,18,221,115,194,252,53,2,246,65,119,
                            86,189,4,69,5,32,3,181,164,70,221,27,124,150,79,26,
                            49,155,203,233,102,115,198,35,109,114,185,175,72,219,
                            192,2,34,177,117,240,192,105,32,175,51,253,150,39,
                            207,140,248,190,185,169,149,207,75,183,232,130,97,
                            134,248,73,211,143,19,129,225,235,131,49,137,183,128,
                            18,192,4,9,96,165,16,73,174,80,145,211,79,163,131,
                            129,25,110,71,101,128,37,44,72,195,58,179,48,222,208,
                            82,102,231,88,16,164,115,66,112,105,3,124,202,235,
                            231,182,144,120,81,54,157,110,145,141,47,19,83,254,
                            24,186,38,28,43,153,64,13,134,24,2,188,89,93,215,233,
                            102,230,147,113,11,153,88,41,148,248,51,156,162,198,
                            60,209,159,4,120,24,123,106,219,3,62,244,204,54,101,
                            212,221,85,235,96,165,173,207,71,19,235,92,209,36,42,
                            167,241,122,133,231,28,241,119,34,32,242,19,78,58,
                            188,119,213,179,183,250,243,74,4,27,17,83,158,100,
                            142,189,22,251,42,168,35,90,143,131,185,187,38,156,
                            83,32,29,31,12,72,32,163,220,129,102,217,108,18,10,
                            52,10,254,150,135,24,39,177,251,154,74,21,110,127,
                            198,85,162,39,21,137,16,204,99,80,229,235,85,246,240,
                            175,52,173,99,157,221,158,39,58,0,177,0,233,148,37,
                            100,17,214,227,69,106,167,10,34,167,87,97,56,8,98,
                            154,151,203,71,228,199,28,131,188,96,255,123,179,253,
                            251,139,8,74,94,166,46,128,214,135,242,197,30,173,47,
                            119,33,242,126,192,219,56,222,234,5,85,176,120,113,
                            125,6,2,52,102,158,226,79,170,232,31,12,63,239,226,
                            154,23,154,166,248,18,244,152,204,138,10,86,142,101,
                            27,35,206,213,157,94,204,3,77,79,234,181,95,127,44,0,
                            121,205,18,85,223,193,186,243,199,211,164,7,230,140,
                            27,120,129,250,182,78,236,34,74,238,122,141,87,200,
                            123,89,68,43,154,9,40,81,221,38,249,153,150,218,217,
                            190,99,5,253,64,15,198,235,145,28,253,193,30,179,99,
                            156,255,233,29,249,95,254,67,208,253,75,254,119,112,
                            53,178,54,245,252,247,150,128,255,67,254,103,96,99,
                            100,248,151,252,207,196,204,202,242,223,252,255,159,
                            0,121,237,254,255,158,171,200,175,158,128,0,42,128,
                            122,242,121,252,53,195,104,10,245,119,163,97,78,171,
                            193,200,235,35,11,59,66,104,73,46,92,22,213,49,186,
                            62,183,116,218,56,29,226,66,202,186,112,191,153,75,
                            209,99,135,253,103,129,208,10,223,174,22,142,20,204,
                            243,24,152,60,187,201,156,8,233,155,81,28,38,215,159,
                            24,162,102,94,61,158,56,19,74,5,32,152,39,174,221,
                            142,80,114,106,214,215,227,240,58,218,116,138,225,32,
                            152,72,149,41,65,103,153,145,204,105,160,61,103,52,1,
                            32,217,113,75,40,95,44,217,118,45,63,139,30,68,131,
                            17,109,253,156,59,180,174,150,110,197,29,103,41,107,
                            184,117,233,83,41,24,184,237,84,80,53,87,24,18,182,
                            142,183,224,235,232,228,97,167,35,131,124,208,116,
                            126,146,218,9,158,86,174,109,249,219,165,163,135,176,
                            143,240,82,219,79,200,80,167,70,169,48,32,238,137,
                            162,63,237,57,12,33,147,30,79,253,197,222,114,23,43,
                            180,108,198,182,187,34,112,177,226,210,130,100,119,
                            82,171,19,147,34,57,145,181,111,199,125,243,153,24,
                            234,63,130,92,16,21,246,203,157,236,93,195,220,180,
                            208,253,251,125,86,46,38,116,206,149,85,185,215,207,
                            17,255,158,89,93,23,34,55,92,225,75,151>>,
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
                        timer:sleep(6000),
                        bm_decryptor:process_object(Payload)
                end),
    meck:expect(test,
                filechunk_sent,
                fun(FileHash, ChunkHash) 
                      when FileHash == File#bm_file.hash,
                           ChunkHash == FileChunk#bm_filechunk.hash ->
                        case bm_db:lookup(bm_filechunk, ChunkHash) of
                            [] ->
                                meck:exception(error, "No chunk in DB");
                            [FC] ->
                                error_logger:info_msg("FileChunk sent test ~p~n", [FC]),
                                ?assertEqual(bm_attachment_srv:progress(FileHash), 1),
                                error_logger:info_msg("FileChunk sent test ~p~n", [FC]),
                                mnesia:clear_table(bm_filechunk),
                                mnesia:dirty_write(bm_filechunk,
                                                   FC#bm_filechunk{data=undefined}),
                                ok
                        end
                end),
    meck:expect(test,
                filechunk_received,
                fun(_FileHash, ChunkHash) ->
                        case bm_db:lookup(bm_filechunk, ChunkHash) of
                            [] ->
                                meck:exception(error, "No chunk in DB");
                            [FC] ->
                                ?assertEqual(FC#bm_filechunk.data, FileChunk#bm_filechunk.data)
                        end
                end),
    bm_db:insert(bm_file, [File]),
    bm_decryptor_sup:add_decryptor(#privkey{pek=Priv}),
    bm_attachment_srv:send_chunk(File#bm_file.hash,
                                 FileChunk#bm_filechunk.hash),
    meck:wait(bm_pow, make_pow, '_', 1600),
    meck:wait(bm_sender, send_broadcast, '_', 1600),
    meck:wait(test, filechunk_sent, '_', 16000),
    meck:validate(test),
    meck:wait(test, filechunk_received, '_', 600000),
    meck:validate(test).
