-module(bm_message_decryptor).

-behaviour(gen_server).

-include("../include/bm.hrl").

%% API
-export([start_link/1]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).
-export([
    decrypt_message/2,
    decrypt_broadcast/2
    ]).

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
start_link(Init) ->
    gen_server:start_link(?MODULE, [Init], []).

decrypt_message(Data, Hash) ->
    Pids = supervisor:which_children(bm_decryptor_sup),
    send_all(Pids, {decrypt, message, Hash, Data}).

decrypt_broadcast(Data, Hash) ->
    Pids = supervisor:which_children(bm_decryptor_sup),
    send_all(Pids, {decrypt, broadcast, Hash, Data}).

encrypt_broadcast(Data) ->
    gen_server:cast(?MODULE, {encrypt, Data}).

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
init([Init]) ->
    bm_dispatcher:register_cryptor(self()),
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
handle_cast({decrypt, Type, Hash, <<IV:16/bytes, 
                              _:16/integer,  %Curve type
                              XLength:16/big-integer, X:XLength/bytes, 
                              YLength:16/big-integer, Y:YLength/bytes, 
                              Data/bytes>> = Payload}, 
            #privkey{address=Address, pek=PrivKey}=State) ->
    MLength = byte_size(Data) - 32,
    <<EMessage:MLength/bytes, HMAC:32/bytes>> = Data,
    R = <<4, X/bytes, Y/bytes>>,
    XP = crypto:compute_key(ecdh, R, PrivKey, secp256k1),
    error_logger:info_msg("XP: ~p~n", [XP]),
    <<E:32/bytes, M:32/bytes>> = crypto:hash(sha512, XP),
    case crypto:hmac(sha256, M, EMessage) of
        HMAC ->
            error_logger:info_msg("Msg to me: ~p~n", [Type]),
            DMessage = crypto:block_decrypt(aes_cbc256, E, IV, EMessage),
            error_logger:info_msg("Message decrypted: ~p~n", [DMessage]),
            case Type of 
                message ->
                    bm_dispetcher:message_arrived(DMessage, Hash, Address);
                broadcast ->
                    bm_dispetcher:broadcast_arrived(DMessage, Hash, Address)
            end;
        _ ->
            error_logger:info_msg("Msg not for me: ~p~n", [Type]),
            not_for_me
    end,
    {noreply, State};

handle_cast({encrypt, Type, Payload}, #state{type=encryptor, key=PubKey}=State) ->
    MLength = byte_size(Payload),
    IV = crypto:rand_bytes(16),
    {KeyR, Keyr} = crypto:generate_key(ecdh, secp256k1),
    XP = crypto:compute_key(ecdh, PubKey, Keyr, secp256k1),
    <<E:32/bytes, M:32/bytes>> = crypto:hash(sha512, XP),
    EMessage = crypto:block_encrypt(aes_cbc256, E, IV, Payload),
    HMAC = crypto:hmac(sha256, M, EMessage),
    case Type of 
        message ->
            bm_dispetcher:message_sent(EMessage);
        broadcast ->
            bm_dispetcher:broadcast_sent(EMessage)
    end,
    {noreply, State};
handle_cast(_Msg, State) ->
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
handle_info(_Info, State) ->
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
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
send_all([], _Msg) ->
    ok;
send_all([Pid|Rest], Msg) ->
    {_, P, _, _} = Pid,
    gen_server:cast(P, Msg),
    send_all(Rest, Msg).
