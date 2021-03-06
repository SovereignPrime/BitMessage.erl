-module(bm_sender).

-behaviour(gen_server).

%% API
-export([start_link/0]).

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
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%%--------------------------------------------------------------------
%% @doc
%% Sends formed Message to all addrs
%%
%% @spec send_broadcast(Message) -> ok
%% @end
%%--------------------------------------------------------------------
send_broadcast(Message) ->
    gen_server:cast(?MODULE, {send, Message}).

%%--------------------------------------------------------------------
%% @doc
%% Register new peer in sender
%%
%% @spec send_broadcast(Message) -> ok
%% @end
%%--------------------------------------------------------------------
register_peer(Socket) ->
    gen_server:cast(?MODULE, {register, Socket}).

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
init([]) ->
    ets:new(addrs, [named_table, public]),
    {ok, #state{}}.

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
handle_cast({send, Message}, #state{sockets=Sockets1, transport=Transport}=State) ->
    Sockets = ets:select(addrs, [{{'$1', '_'}, [], ['$1']}]),
    broadcast(Message, Sockets, Transport),
    {noreply, State};
handle_cast({register, Socket}, #state{sockets=Sockets}=State) ->
    Time = bm_types:timestamp(),
    ets:insert(addrs, {Socket, Time}), 
    {noreply, State#state{sockets=[Socket|Sockets]}};
handle_cast({unregister, Socket}, #state{sockets=Sockets}=State) ->
    ets:delete(addrs, Socket), 
    {noreply, State#state{sockets=lists:delete( Socket, Sockets )}};
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
broadcast(_, [], _) ->
    ok;
broadcast(Message, [Socket| Rest], Transport) ->
    inet:setopts(Socket, [{send_timeout, 100}]),
    case Transport:send(Socket, Message) of
        ok ->
            ok;
        {error, timeout} ->
            ok;
        {error, _} ->
            error_logger:warning_msg("Deleting socket: ~p~n", [Socket]),
            ets:delete(addrs, Socket)
    end,
    broadcast(Message, Rest, Transport).
