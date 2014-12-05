-module(bm_sender).

-behaviour(gen_server).

%% API
-export([
         start_link/0,
         start_link/1
        ]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).
-export([
    register_peer/1,
    unregister_peer/1,
    send_broadcast/1
    ]).

-record(state, {transport=gen_tcp, sockets=[]}).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @end
%%--------------------------------------------------------------------
-spec start_link() -> {ok, pid()} | ignore | {error, string()}.  % {{{1
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [gen_tcp], []).

-spec start_link(atom()) -> {ok, pid()} | ignore | {error, string()}.  % {{{1
start_link(Transport) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Transport], []).

%%--------------------------------------------------------------------
%% @doc
%% Sends formed Message to all addrs
%%
%% @end
%%--------------------------------------------------------------------
-spec send_broadcast(Message) -> ok when  % {{{1
      Message :: iodata().
send_broadcast(Message) ->
    gen_server:cast(?MODULE, {send, Message}).

%%--------------------------------------------------------------------
%% @doc
%% Register new peer in sender
%%
%% @end
%%--------------------------------------------------------------------
-spec register_peer(gen_tcp:socket()) -> ok.  % {{{1
register_peer(Socket) ->
    gen_server:cast(?MODULE, {register, Socket}).

%%--------------------------------------------------------------------
%% @doc
%% Unregister peer in sender
%%
%% @end
%%--------------------------------------------------------------------
-spec unregister_peer(gen_tcp:socket()) -> ok.  % {{{1
unregister_peer(Socket) ->
    gen_server:cast(?MODULE, {unregister, Socket}).

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
init([Transport]) ->  % {{{1
    ets:new(addrs, [named_table, public]),
    {ok, #state{transport=Transport}}.

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
handle_cast({send,  % {{{1
             Message},
            #state{sockets=Sockets1,
                   transport=Transport}=State) ->
    Sockets = ets:select(addrs, [{{'$1', '_'}, [], ['$1']}]),
    broadcast(Message, Sockets, Transport),
    {noreply, State};
handle_cast({register, Socket}, #state{sockets=Sockets}=State) ->  % {{{1
    Time = bm_types:timestamp(),
    ets:insert(addrs, {Socket, Time}), 
    {noreply, State#state{sockets=[Socket|Sockets]}};
handle_cast({unregister, Socket}, #state{sockets=Sockets}=State) ->  % {{{1
    ets:delete(addrs, Socket), 
    {noreply, State#state{sockets=lists:delete( Socket, Sockets )}};
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

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Broadcasts `Message` to all `Sockets` through `Transport`
%%
%% @end
%%--------------------------------------------------------------------
-spec broadcast(iodata(), [gen_tcp:socket()], atom()) -> ok. % {{{1
broadcast(_, [], _) ->
    ok;
broadcast(Message, [Socket| Rest], Transport) ->
    %inet:setopts(Socket, [{send_timeout, 100}]),
    case Transport:send(Socket, Message) of
        ok ->
            %error_logger:info_msg("Sent: ~p~n", [Socket]),
            broadcast(Message, Rest, Transport);
        {error, timeout} ->
            %error_logger:info_msg("Send timeout: ~p~n", [Socket]),
            broadcast(Message, Rest, Transport);
        {error, R} ->
            error_logger:info_msg("Send error: ~p~n", [R]),
            error_logger:warning_msg("Deleting socket: ~p~n", [Socket]),
            ets:delete(addrs, Socket),
            broadcast(Message, Rest, Transport)
    end.
