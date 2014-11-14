-module(bm_message_decryptor).

-behaviour(gen_server).

-include("../include/bm.hrl").

%% API
-export([start_link/1]).

%% gen_server callbacks
-export([init/1,  % {{{1
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).  % }}}
-export([  % {{{1
    decrypt_message/2,
    decrypt_broadcast/2
    ]).  % }}}

-record(state, {type, key}).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link(Init) ->  % {{{1
    gen_server:start_link(?MODULE, [Init], []).

%%--------------------------------------------------------------------
%% @doc
%% Adds message to decrypt
%%
%% @end
%%--------------------------------------------------------------------
-spec decrypt_message(binary(), binary()) -> ok. % {{{1
decrypt_message(Data, Hash) ->
    Pids = supervisor:which_children(bm_decryptor_sup),
    send_all(Pids, {decrypt, message, Hash, Data}).


%%--------------------------------------------------------------------
%% @doc
%% Adds broadcast to decrypt
%%
%% @end
%%--------------------------------------------------------------------
-spec decrypt_broadcast(binary(), binary()) -> ok. % {{{1
decrypt_broadcast(Data, Hash) ->
    Pids = supervisor:which_children(bm_decryptor_sup),
    send_all(Pids, {decrypt, broadcast, Hash, Data}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init([Init]) ->  % {{{1
    {ok, Init}.

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
handle_call(_Request, _From, State) ->  % {{{1
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
handle_cast({decrypt, Type, Hash, <<IV:16/bytes,   % {{{1
                              _:16/integer,  %Curve type
                              XLength:16/big-integer, X:XLength/bytes, 
                              YLength:16/big-integer, Y:YLength/bytes, 
                              Data/bytes>> = Payload}, 
            #privkey{address=Address,
                     pek=PrivKey}=State) ->
    MLength = byte_size(Data) - 32,
    <<EMessage:MLength/bytes, HMAC:32/bytes>> = Data,
    XPad = << <<0>> || _<- lists:seq(1, 32 - XLength)>>,
    YPad = << <<0>> || _<- lists:seq(1, 32 - YLength)>>,
    R = <<4, XPad/bytes, X/bytes, YPad/bytes, Y/bytes>>,
    XP = crypto:compute_key(ecdh, R, PrivKey, secp256k1),
    <<E:32/bytes, M:32/bytes>> = crypto:hash(sha512, XP),
    case crypto:hmac(sha256, M, EMessage) of
        HMAC ->
            DMessage = crypto:block_decrypt(aes_cbc256, E, IV, EMessage),
            error_logger:info_msg("Message decrypted: ~p~n", [DMessage]),
            case Type of 
                message ->
                    bm_dispatcher:message_arrived(DMessage, Hash, Address);
                broadcast ->
                    bm_dispatcher:broadcast_arrived(DMessage, Hash, Address)
            end;
        _ ->
            not_for_me
    end,
    {noreply, State};

handle_cast(_Msg, State) ->  % {{{1
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
handle_info(_Info, State) ->  % {{{1
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
terminate(_Reason, _State) ->  % {{{1
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->  % {{{1
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% @doc Sends cast to all decryptors
%%
-spec send_all(PIDs, Msg) -> ok when
      PIDs :: [pid()],
      Msg :: term().
send_all([], _Msg) ->  % {{{1
    ok;
send_all([Pid|Rest], Msg) ->  % {{{1
    {_, P, _, _} = Pid,
    gen_server:cast(P, Msg),
    send_all(Rest, Msg).
