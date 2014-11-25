-module(bm_socket).

-behaviour(gen_server).

-include("../include/bm.hrl").

%% API
-export([
         start_link/2,
         start_link/1
        ]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-record(state,
        {
         id :: non_neg_integer(),
         socket :: gen_tcp:socket(),
         transport :: module(),
         remote_addr :: #network_address{},
         buffer = <<>> :: binary()
        }).

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
start_link(Id) ->  % {{{1
    start_link(Id, gen_tcp).

%%--------------------------------------------------------------------
%% @doc
%% Starts the server w/`Transport`
%%
%% @spec start_link(Transport) -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link(Id, Transport) ->  % {{{1
    gen_server:start_link({local, {?MODULE, Id}}, ?MODULE, [Id, Transport], []).
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
init([Id, Transport]) ->  % {{{1
    bm_db:wait_db(),
    #network_address{ip=Ip,
                      port=Port} = RAddr = bm_db:get_net(),
    case Transport:connect(Ip,
                         Port,
                         [
                          inet,
                          binary,
                          {active,true},
                          {reuseaddr, true},
                          {packet, raw}
                         ],
                         1000) of
        {ok, Socket} ->
            Transport:send(Socket, bm_protocol:connect(Id, RAddr)),
            {ok, #state{
                    id=Id,
                    socket=Socket,
                    transport=Transport
                   }};
        {error, Reason} ->
            error_logger:warning_msg("Error connecting to ~p:~p~nReason: ~p~n", [Ip, Port, Reason]),
            init([Transport])
    end.

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
handle_info({tcp,
             Socket,
             Data},
            #state{transport=Transport,
                   socket=Socket}=State) ->  % {{{1
    {noreply, check_packet(Data, State)};
handle_info({tcp_closed,
             Socket},
            #state{socket=Socket}=State) ->  % {{{1
    {stop, normal, State};
handle_info({tcp_error,
             Socket,
             _Data},
            #state{transport=Transport,
                   socket=Socket}=State) ->  % {{{1
    {stop, normal, State};
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
%% Check packet correctnes
%%
%% @end
%%--------------------------------------------------------------------
-spec check_packet(binary(), #state{}) -> #state{}.  % {{{1

%% Packet has full message and more  {{{2
check_packet(<<?MAGIC,
               Command:12/bytes,
               Length:32,
               Check:4/bytes,
               Packet/bytes>>,
             State) when size(Packet) > Length ->
    <<NPacket:Length/bytes, Rest/bytes>> = Packet,
    bm_protocol:message(Command, Length, NPacket),
    check_packet(Rest, State);

%% Packet has only full message  {{{2
check_packet(<<?MAGIC,
               Command:12/bytes,
               Length:32,
               Check:4/bytes,
               Packet/bytes>>,
             State) when size(Packet) == Length ->
    case crypto:hash(sha512, Packet) of
        <<Check:32/bits, _/bits>> ->
            %update_peer_time(State),
            bm_protocol:message(Command, Length, Packet),
            State#state{buffer = <<>>};
        _ ->
            State#state{buffer = <<>>}
    end;

%% Packet doesn't have full message  {{{2
check_packet(<<?MAGIC,
               _Command:12/bytes,
               Length:32,
               _Check:4/bytes,
               Packet/bytes>>,
             State) when size(Packet) < Length ->
    State;

%% Default  % {{{2
check_packet(_, State) ->
    State.

%%% Updates timestamp peer was active
%-spec update_peer_time(#state{}) -> any().  % {{{1  ???
%update_peer_time(#state{socket=Socket, stream=Stream}) ->
%    Time = bm_types:timestamp(),
%    {ok, {Ip, Port}} = inet:peername(Socket),
%    bm_db:insert(addr,
%                 [#network_address{time=Time,
%                                   ip=Ip,
%                                   port=Port,
%                                   stream=Stream}]).
