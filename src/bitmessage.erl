-module(bitmessage).
-include("../include/bm.hrl").

-behaviour(gen_server).

%% Bitmessage API {{{1
-export([
         start_link/0,
         register_receiver/1,
         send_message/1,
         send_message/4,
         send_message/5,
         send_broadcast/4,
         subscribe_broadcast/1,
         get_attachment/2,
         get_message/1,
         generate_address/0
]).

%% Bitmessage callbacks {{{1
-export([
         received/1,
         sent/1,
         downloaded/1,
         filechunk_received/2,
         filechunk_sent/2,
         key_ready/1,
         connected/1,
         disconnected/1
        ]).

%% gen_server callbacks  {{{1
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).
% }}}

-record(state, {callback}).

%%%-----------------------------------------------------------------------------
%%% Bitmessage behaviour callbacks {{{1
%%%-----------------------------------------------------------------------------


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 
%% @doc Hash type for IDs of bitmessage objects
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-type hash() :: binary().  % {{{2


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Called when new message or broadcast received with ID of sent object
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-callback received(hash()) -> ok.  % {{{2

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Called when new message or broadcast sent with ID of sent object
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-callback sent(hash()) -> ok.  % {{{2

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Called when new key data is generated
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-callback key_ready(BMAddress) -> ok when  % {{{2
      BMAddress :: binary().

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Called when attachment download complete
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-callback downloaded(hash()) -> ok.  % {{{2

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Called when FileChunk sent
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-callback filechunk_sent(Hash, ChunkHash) -> ok when  % {{{2
      Hash :: hash(),
      ChunkHash :: hash().

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Called when new FileChunk received
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-callback filechunk_received(Hash, ChunkHash) -> ok when  % {{{2
      Hash :: hash(),
      ChunkHash :: hash().

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Called when new host is connected with number of peers as argument
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-callback connected(non_neg_integer()) -> ok.  % {{{2

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Called when new host is disconnected with number of peers as argument
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-callback disconnected(non_neg_integer()) -> ok.  % {{{2


%%%-----------------------------------------------------------------------------
%%% Bitmessage API {{{1
%%%-----------------------------------------------------------------------------


%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
-spec start_link() ->  {ok, pid()} | % {{{2
                       ignore |
                       {error, term()}.
start_link() ->
    Callback = application:get_env(bitmessage, receiver, undefined),
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Callback], []).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Send a message w/standard enc
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-spec send_message(From, To, Subject, Text) -> ok when  % {{{2
      From :: binary(),
      To :: binary(),
      Subject :: binary(),
      Text :: binary().
send_message(From, To, Subject, Text) ->
    send_message(#message{from=From,
                          type=?MSG,
                          to=To,
                          subject=Subject,
                          text=Text}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Send a message w/attachments
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-spec send_message(From, To, Subject, Text, Attachments) -> ok when  % {{{2
      From :: binary(),
      To :: binary(),
      Subject :: binary(),
      Text :: binary(),
      Attachments :: [Attachment],
      Attachment :: string().
send_message(From, To, Subject, Text, Attachments) ->
    send_message(#message{from=From,
                          type=?MSG,
                          to=To,
                          subject=Subject,
                          enc=3,
                          attachments=Attachments,
                          text=Text}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Send custom message record (use w/caution)
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-spec send_message(#message{}) -> ok. % {{{2
send_message(Message) ->
    NMessage = Message#message{hash=crypto:hash(sha512, Message#message.text),
                               folder=sent},
    mnesia:transaction(fun() ->
                               mnesia:write(message, NMessage, write)
                       end),
    gen_server:cast(?MODULE, {send, NMessage}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Send a broadcast w/standard enc
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-spec send_broadcast(From, Subject, Text, Encoding) -> ok when  % {{{2
      From :: binary(),
      Subject :: binary(),
      Text :: binary(),
      Encoding :: integer().
send_broadcast(From, Subject, Text, Encoding) ->
    send_message(#message{from=From,
                          subject=Subject,
                          text=Text,
                          type=?BROADCAST,
                          enc=Encoding}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Subscribe to broadcasts from address
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-spec subscribe_broadcast(binary()) -> supervisor:startchild_ret().  % {{{2
subscribe_broadcast(Address) ->
    {PrivKey, _} = bm_auth:broadcast_key(Address),

     PK = #privkey{hash=PrivKey,
                   pek=PrivKey,
                   address=Address,
                   time=bm_types:timestamp()},
    bm_db:insert(privkey, [PK]),
    bm_decryptor_sup:add_decryptor(PK).
    
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Get attachment
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-spec get_attachment(binary(), string()) -> ok.  % {{{2
get_attachment(Hash, Path) ->
    gen_server:cast(?MODULE, {attachment, Hash, Path}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Generate bitmessage keypair and address
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-spec generate_address() -> ok.  % {{{2
generate_address() ->
    gen_server:cast(?MODULE, generate_address).

-spec register_receiver(module()) -> ok.  % {{{2
register_receiver(Callback) ->
    gen_server:cast(?MODULE, {receiver, Callback}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Returns number of active connections
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% @doc Get incoming message from db by hash
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-spec get_message(hash()) -> {ok, #message{}}.  % {{{2
get_message(Hash) ->
    [Msg] = bm_db:lookup(message, Hash),
    {ok, Msg}.


%%%--------------------------------------------------------------------
%%%
%%% Callback proxies  % {{{1
%%%
%%%--------------------------------------------------------------------
-spec received(hash()) -> ok.  % {{{2
received(Hash) ->
    error_logger:info_msg("Received message: ~p~n", [bm_types:binary_to_hexstring(Hash)]),
    gen_server:cast(?MODULE, {event, received, [ Hash ]}).

-spec sent(hash()) -> ok.  % {{{2
sent(Hash) ->
    error_logger:info_msg("Sent message: ~p~n", [bm_types:binary_to_hexstring(Hash)]),
    gen_server:cast(?MODULE, {event, sent, [ Hash ]}).

-spec downloaded(hash()) -> ok.  % {{{2
downloaded(Hash) ->
    error_logger:info_msg("Attachment download complete: ~p~n",
                          [bm_types:binary_to_hexstring(Hash)]),
    gen_server:cast(?MODULE, {event, downloaded, [ Hash ]}).

-spec filechunk_sent(hash(), hash()) -> ok.  % {{{2
filechunk_sent(Hash, ChunkHash) ->
    error_logger:info_msg("Filechunk ~p sent message: ~p~n", [bm_types:binary_to_hexstring(ChunkHash), bm_types:binary_to_hexstring(Hash)]),
    gen_server:cast(?MODULE, {event, filechunk_sent, [ Hash, ChunkHash ]}).

-spec filechunk_received(hash(), hash()) -> ok.  % {{{2
filechunk_received(Hash, ChunkHash) ->
    error_logger:info_msg("Filechunk ~p received message: ~p~n", [bm_types:binary_to_hexstring(ChunkHash), bm_types:binary_to_hexstring(Hash)]),
    gen_server:cast(?MODULE, {event, filechunk_received, [ Hash, ChunkHash ]}).

-spec key_ready(binary()) -> ok.  % {{{2
key_ready(Address) ->
    error_logger:info_msg("New address generated: ~p~n", [Address]),
    gen_server:cast(?MODULE, {event, key_ready, [ Address ]}).

-spec connected(non_neg_integer()) -> ok.  % {{{2
connected(N) ->
    error_logger:info_msg("New peer. Number of peers: ~p~n",
                          [N]),
    gen_server:cast(?MODULE, {event, connected, [ N ]}).

-spec disconnected(non_neg_integer()) -> ok.  % {{{2
disconnected(N) ->
    error_logger:info_msg("Peer disconnected. Number of peers: ~p~n",
                          [N]),
    gen_server:cast(?MODULE, {event, disconnected, [ N ]}).

%%%===================================================================
%%% gen_server callbacks  {{{1
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @end
%%--------------------------------------------------------------------
-spec init([module()]) -> {ok, #state{}, non_neg_integer()}.  % {{{2
init([Callback]) ->
    bm_db:wait_db(),
    %%%%%{ok, #state{callback=Callback}}.
    {ok, #state{callback=Callback}, 0}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast({send, Message}, State) ->  % {{{2
    error_logger:info_msg("Sending  ~p~n", [Message]),
    bm_encryptor_sup:add_encryptor(Message),
    {noreply, State};
handle_cast({attachment, Hash, Path}, State) ->  % {{{2
    bm_attachment_sup:download_attachment(Hash, Path),
    {noreply, State};
handle_cast({register, Module}, State) ->  % {{{2
    {noreply, State#state{callback=Module}};
handle_cast(generate_address, State) ->  % {{{2
    bm_address_generator:generate_random_address(make_ref(), 1, false),
    {noreply, State};
handle_cast({event, Fun, Args}, #state{callback=undefined}=State) ->  % {{{2
    error_logger:info_msg("Callback ~p:~p(~p) called", [undefined, Fun, Args]),
    {noreply, State};
handle_cast({event, Fun, Args}, #state{callback=Callback}=State) ->  % {{{2
    error_logger:info_msg("Callback ~p:~p(~p) called", [Callback, Fun, Args]),
    try
        apply(Callback, Fun, Args),
        {noreply, State}
    catch
        error:_ ->
            {noreply, State}
    end;
handle_cast(Msg, State) ->  % {{{2
    error_logger:warning_msg("Wrong cast ~p recved in ~p~n", [Msg, ?MODULE]),
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info(timeout, State) ->  % {{{2
    Messages = bm_db:select(message,
                            [{#message{folder=sent,
                                       status='new',
                                       _='_'},
                              [],
                              ['$_']},
                             {#message{folder=sent,
                                       status='wait_pubkey',
                                       _='_'},
                              [],
                              ['$_']},
                             {#message{folder=sent,
                                       status='encrypt_message',
                                       _='_'},
                              [],
                              ['$_']}],
                            10000),
    error_logger:info_msg("Messages in progress: ~p~n", [Messages]),
    lists:foreach(fun(E) ->
                          bm_encryptor_sup:add_encryptor(E)
                  end,
                  lists:flatten(Messages)),
    Downloads = bm_db:match(bm_file, #bm_file{status=downloading,
                                              _='_'}),
    error_logger:info_msg("Downloads in progress: ~p~n", [Downloads]),
    lists:foreach(fun(#bm_file{
                         hash=Hash,
                         path=Path
                        }) ->
                          bm_attachment_sup:download_attachment(Hash, Path)
                  end,
                  Downloads),
    {noreply, State};
handle_info(_Info, State) ->  % {{{2
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->  % {{{2
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->  % {{{2
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
