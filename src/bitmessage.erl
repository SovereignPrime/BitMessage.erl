-module(bitmessage).
-compile([export_all]).
-include("../include/bm.hrl").

send_message(From, To, Subject, Text) ->  % {{{1
    bm_dispatcher:send_message(#message{from=From, to=To, subject=Subject, text=Text}).

send_message(From, To, Subject, Text, Encoding) ->  % {{{1
    bm_dispatcher:send_message(#message{from=From, to=To, subject=Subject, text=Text, enc=Encoding}).

send_broadcast(From, Subject, Text, Encoding) ->  % {{{1
    bm_dispatcher:send_broadcast(#message{from=From, subject=Subject, text=Text, enc=Encoding}).

subscribe_broadcast(Address) ->  % {{{1
    #address{version=V, stream=S, ripe=R} = bm_auth:decode_address(Address),
    <<PrivKey:32/bytes, _/bytes>> = crypto:hash(sha512, <<(bm_types:encode_varint(V))/bytes, (bm_types:encode_varint(S))/bytes, R/bytes>>),
    PK = #privkey{hash=PrivKey, pek=PrivKey, address=Address, time=bm_types:timestamp()},
    bm_db:insert(privkey, [PK]),
    bm_decryptor_sup:add_decryptor(PK).
    

generate_address(Ref) ->  % {{{1
    bm_address_generator:generate_random_address(make_ref(), 1, false, Ref).

register_receiver(Module) ->  % {{{1
    bm_dispatcher:register_receiver(Module).

get_message(Hash) ->  % {{{1
    [Msg] = bm_db:lookup(incoming, Hash),
    {ok, Msg}.
