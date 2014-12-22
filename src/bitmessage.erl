-module(bitmessage).
-compile([export_all]).
-include("../include/bm.hrl").

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 
%% @doc Hash type for IDs of bitmessage objects
-type hash() :: binary().


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Called when new message or broadcast received with ID of sent object
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-callback received(hash()) -> ok.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Called when new message or broadcast sent with ID of sent object
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-callback sent(hash()) -> ok.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Called when new key data is generated
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-callback key_ready(BMAddress) -> ok when
      BMAddress :: binary().

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Called when new host is connected with number of peers as argument
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-callback connected(non_neg_integer()) -> ok.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Called when new host is disconnected with number of peers as argument
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-callback disconnected(non_neg_integer()) -> ok.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Send a message w/standard enc
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-spec send_message(From, To, Subject, Text) -> ok when  % {{{1
      From :: binary(),
      To :: binary(),
      Subject :: binary(),
      Text :: binary().
send_message(From, To, Subject, Text) ->
    bm_dispatcher:send_message(#message{from=From,
                                        to=To,
                                        subject=Subject,
                                        text=Text}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Send message w/custom enc
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-spec send_message(From, To, Subject, Text, Encoding) -> ok when  % {{{1
      From :: binary(),
      To :: binary(),
      Subject :: binary(),
      Text :: binary(),
      Encoding :: integer().
send_message(From, To, Subject, Text, Encoding) ->
    bm_dispatcher:send_message(#message{from=From,
                                        to=To,
                                        subject=Subject,
                                        text=Text,
                                        enc=Encoding}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Send a broadcast w/standard enc
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-spec send_broadcast(From, Subject, Text, Encoding) -> ok when  % {{{1
      From :: binary(),
      Subject :: binary(),
      Text :: binary(),
      Encoding :: integer().
send_broadcast(From, Subject, Text, Encoding) ->
    bm_dispatcher:send_broadcast(#message{from=From,
                                          subject=Subject,
                                          text=Text,
                                          enc=Encoding}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Subscribe to broadcasts from address
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-spec subscribe_broadcast(binary()) -> supervisor:startchild_ret().  % {{{1
subscribe_broadcast(Address) ->
    #address{version=V,
             stream=S,
             ripe=R} = bm_auth:decode_address(Address),

    <<PrivKey:32/bytes,
      _/bytes>> = crypto:hash(sha512,
                              <<(bm_types:encode_varint(V))/bytes,
                                (bm_types:encode_varint(S))/bytes,
                                R/bytes>>),
    PK = #privkey{hash=PrivKey,
                  pek=PrivKey,
                  address=Address,
                  time=bm_types:timestamp()},

    bm_db:insert(privkey, [PK]),
    bm_decryptor_sup:add_decryptor(PK).
    

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Generate bitmessage keypair and address
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-spec generate_address(fun(({address, binary()}) -> any())) -> ok.  % {{{1
generate_address(Fun) ->
    bm_address_generator:generate_random_address(make_ref(), 1, false, Fun).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Registers callback module
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-spec start_link(atom()) -> ok.  % {{{1
start_link(Module) ->
    bm_dispatcher:register_receiver(Module).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Get incoming message from db by hash
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-spec get_message(hash()) -> {ok, #message{}}.  % {{{1
get_message(Hash) ->
    [Msg] = bm_db:lookup(message, Hash),
    {ok, Msg}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Callback examples  % {{{1
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-spec received(hash()) -> ok.
received(Hash) ->  % {{{1
    error_logger:info_msg("Received message: ~p~n", [bm_types:binary_to_hexstring(Hash)]),
    ok.

-spec sent(hash()) -> ok.
sent(Hash) ->  % {{{1
    error_logger:info_msg("Sent message: ~p~n", [bm_types:binary_to_hexstring(Hash)]),
    ok.
-spec key_ready(binary()) -> ok.
key_ready(Address) ->  % {{{1
    error_logger:info_msg("New address generated: ~p~n", [Address]),
    ok.
-spec connected(non_neg_integer()) -> ok.
connected(N) ->  % {{{1
    error_logger:info_msg("New peer. Number of peers: ~p~n",
                          [N]),
    ok.
-spec disconnected(non_neg_integer()) -> ok.
disconnected(N) ->  % {{{1
    error_logger:info_msg("Peer disconnected. Number of peers: ~p~n",
                          [N]),
    ok.
