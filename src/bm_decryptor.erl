-module(bm_decryptor).

-behaviour(gen_fsm).
-include("../include/bm.hrl").

%% API functions
-export([
         start_link/1,
         process_object/1,
         callback/1
        ]).

%% gen_fsm callbacks
-export([init/1,
         payload/2,
         preprocess/2,
         decrypt/2,
         inventory/2,
         handle_event/3,
         handle_sync_event/4,
         handle_info/3,
         terminate/3,
         code_change/4]).

-record(state,
        {
         hash :: binary(),
         stream=1 :: non_neg_integer(),
         version=1 :: non_neg_integer(),
         time :: non_neg_integer(),
         payload :: binary(),
         encrypted :: binary(),
         decrypted :: binary(),
         object :: object_type(),
         callback=bitmessage :: module(),
         keys :: term()
        }).

%%%===================================================================
%%% API functions  {{{1
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Creates a gen_fsm process which calls Module:init/1 to
%% initialize. To ensure a synchronized start-up procedure, this
%% function does not return until Module:init/1 has returned.
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link(Keys) ->% {{{2
    gen_fsm:start_link({local, ?MODULE}, ?MODULE, [Keys], []).

%%--------------------------------------------------------------------
%% @doc
%% Starts object decoding
%% @end
%%--------------------------------------------------------------------
-spec process_object(Payload) -> ok when
      Payload :: binary().
process_object(Payload) ->  % {{{2
    gen_fsm:send_event(?MODULE, Payload).

%%--------------------------------------------------------------------
%% @doc
%% Starts object decoding
%% @end
%%--------------------------------------------------------------------
-spec callback(module()) -> ok.
callback(Module) ->  % {{{2
    error_logger:info_msg("Setting callback to ~p~n", [Module]),
    gen_fsm:send_all_state_event(?MODULE, {callback, Module}).

%%%===================================================================
%%% gen_fsm callbacks  {{{1
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_fsm is started using gen_fsm:start/[3,4] or
%% gen_fsm:start_link/[3,4], this function is called by the new
%% process to initialize.
%%
%% @spec init(Args) -> {ok, StateName, State} |
%%                     {ok, StateName, State, Timeout} |
%%                     ignore |
%%                     {stop, StopReason}
%% @end
%%--------------------------------------------------------------------
init([Keys]) ->% {{{2
    {ok,
     inventory,
     #state{keys=Keys}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% There should be one instance of this function for each possible
%% state name. Whenever a gen_fsm receives an event sent using
%% gen_fsm:send_event/2, the instance of this function with the same
%% name as the current state name StateName is called to handle
%% the event. It is also called if a timeout occurs.
%%
%% @spec state_name(Event, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState}
%% @end
%%--------------------------------------------------------------------
inventory(<<_Nonce:64/big-integer, % {{{2
            Time:64/big-integer,
            Type:32/big-integer,
            Packet/bytes>> = Payload,
          State) ->
    <<Hash:32/bytes, _/bytes>> = bm_auth:dual_sha(Payload),

    IsPOW = bm_pow:check_pow(Payload),
    IsOld = not check_ttl(Time, Type),
    if IsPOW andalso not IsOld ->
           {Version, R} = bm_types:decode_varint(Packet),
           {Stream, R1} = bm_types:decode_varint(R),
           case bm_db:lookup(inventory, Hash) of
               [_] ->
                   {next_state,
                    inventory,
                    State};
               [] ->
                   error_logger:info_msg("Received object: ~p~n",
                                         [bm_types:binary_to_hexstring( Hash )]),
                   bm_db:insert(inventory,
                                [ #inventory{hash=Hash,
                                             payload=Payload,
                                             type=Type,
                                             time=Time,
                                             stream=Stream} ]),
                   bm_sender:send_broadcast(
                     bm_message_creator:create_inv([ Hash ])),
                   error_logger:info_msg("Requested Type: ~p Ver: ~p Size: ~p~n",
                                         [Type,
                                          Version,
                                          size(R)]),

                   {next_state,
                    preprocess,
                    State#state{
                      hash = Hash,
                      version = Version,
                      stream = Stream,
                      time = Time,
                      payload = Payload,
                      encrypted = R1,
                      object = Type
                     },
                    0}
           end;
       true ->
           {next_state,
            inventory,
            State}
    end;
inventory(Event, State) ->
    %error_logger:info_msg("Wrong event ~p state ~p~n", [Event, State]),
    {next_state,
     inventory,
     State}.

-spec preprocess(term(), #state{}) -> {next_state,  % {{{2
                                       atom(),
                                       #state{}} | 
                                      {next_state,
                                       atom(),
                                       #state{},
                                       non_neg_integer()}.
preprocess(timeout,
           #state{
              object=?GET_PUBKEY,  % {{{3
              version=3,
              stream=Stream,
              payload=Payload,
              hash=Hash,
              encrypted=Encrypted
             } = State) ->

    RIPE = bm_auth:denormalyze_ripe(Encrypted),
    case bm_db:lookup(privkey, RIPE) of
        [#privkey{hash=RIPE,
                  address=Addr,
                  enabled=true}=PrKey] ->
            #address{version=3,
                     stream=Stream,
                     ripe=Ripe} = bm_auth:decode_address(Addr),
            error_logger:info_msg("It's my address - sending pubkey~n"),
            bm_sender:send_broadcast(bm_message_creator:create_pubkey(PrKey)),
            {next_state,
             inventory,
             State};
        [] ->
            {next_state,
             inventory,
             State}
    end;
preprocess(timeout,
           #state{
              object=?PUBKEY,  % {{{3
              time=Time,
              version=3,
              encrypted=Data
             } = State) ->
    <<_BBitField:32/big-integer,
      PSK:64/bytes,
      PEK:64/bytes,
      Rest/bytes>> = Data,
    Ripe = bm_auth:generate_ripe(binary_to_list(<<4, PSK/bytes, 4, PEK/bits>>)),
    {NTpB, R} = bm_types:decode_varint(Rest),
    {PLEB, _R1} = bm_types:decode_varint(Rest),
    Pubkey = #pubkey{hash=Ripe,
                     data=Data, % Seems useless ???
                     time=Time,
                     ntpb=NTpB,
                     pleb=PLEB,
                     psk=PSK,
                     pek=PEK},
    bm_db:insert(pubkey, [Pubkey]),
    bm_message_encryptor:pubkey(Pubkey),
    {next_state,
     inventory,
     State};
preprocess(timeout,
           #state{
              object=?PUBKEY,  % {{{3
              version=4,
              encrypted=Data
             } = State) ->

    <<_Tag:32/bytes, Encrypted/bytes>> = Data,
    {next_state,
     decrypt,
     State#state{encrypted=Encrypted},
     0};
preprocess(timeout,
           #state{
              object=?MSG,  % {{{3
              payload=Payload,
              hash=Hash,
              encrypted=Encrypted
             } = State) ->
    case check_ackdata(Encrypted) of
        true ->
            error_logger:info_msg("This is ACK for me"),
            {next_state,
             inventory,
             State,
             0};
        false ->
            error_logger:info_msg("This is not ACK for me, trying to decrypt"),
            {next_state,
             decrypt,
             State,
             0}
    end;
preprocess(timeout,
           #state{
              object=?BROADCAST,  % {{{3
              version=Version,
              payload=Payload,
              hash=Hash,
              encrypted=Data
             } = State) when Version == 4; Version == 5 ->
    <<_Tag:32/bytes, Encrypted/bytes>> = Data,
    {next_state,
     decrypt,
     State#state{encrypted=Encrypted},
     0};
preprocess(timeout,
           #state{
              object=?FILECHUNK,  % {{{3
              payload=Payload,
              hash=Hash,
              encrypted = <<ChunkHash:64/bytes,
                            Encrypted/bytes>>
             } = State) ->
    error_logger:info_msg("Filechunk received: ~p~n", [ChunkHash]),
    case bm_db:lookup(bm_filechunk, ChunkHash) of
        [#bm_filechunk{data=undefined}=FC] ->
        
            bm_db:insert(bm_filechunk, [FC#bm_filechunk{status=received,
                                                        payload=Payload}]),
            {next_state,
             decrypt,
             State#state{encrypted=Encrypted,
                         keys=ChunkHash},
            0};
        _ ->
            {next_state,
             inventory,
             State}
    end;
preprocess(timeout,
           #state{
              object=?GETFILECHUNK,  % {{{3
              version=1,
              encrypted=Data,
              callback=Callback
             } = State) ->
    <<FileHash:64/bytes, ChunkHash:64/bytes>> = Data,
    bm_attachment_srv:send_chunk(FileHash, ChunkHash, Callback),
    {next_state,
     inventory,
     State};
preprocess(timeout,
           State) ->
    {next_state,
     inventory,
     State};
preprocess(Event,  % {{{3
           State) ->
    %error_logger:warning_msg("Wrong event ~p in ~p state ~p~n", [Event, State, ?MODULE_STRING]),
    {next_state,
     preprocess,
     State,
    0}.
decrypt(timeout, % {{{2
        #state{
           hash=Hash,
           keys=Keys,
           encrypted = Payload
          } = State) ->
    error_logger:info_msg("Starting ~p decrypting", [Hash]),
    case bm_message_decryptor:decrypt(Payload) of
        {decrypted, Address, DMessage} ->
            error_logger:info_msg("Message decrypted: ~p~n", [DMessage]),
            {next_state,
             payload,
             State#state{
               decrypted=DMessage,
               keys=case Address of
                        undefined->
                            Keys;
                        _ -> 
                            #privkey{address=Address}
                    end
              },
             0};
        _H ->
            {next_state,
             inventory,
             State}
    end;
decrypt(_Event, State) ->% {{{2
    {next_state, decrypt, State, 0}.

payload(timeout,  % {{{2
        #state{
           hash=Hash,
           object=Type,
           payload=Payload,
           decrypted=Data,
           callback=Callback,
           keys=#privkey{address=Address}
          } = State) when Type == ?MSG; Type == ?BROADCAST ->
    #address{version=AddrVer,
             stream=Stream, % TODO: Is this stream ok??
             ripe=RIPE}=bm_auth:decode_address(Address),
    {AV, R1} = bm_types:decode_varint(Data),
    {AVer, R2} = case bm_types:decode_varint(R1) of
                     {Stream, R} ->
                         {AV, R};
                     {A, R} ->
                         {Stream, RO} = bm_types:decode_varint(R),
                         {A, RO}
                 end,
    <<_BField:32/big-integer, PSK:64/bytes, PEK:64/bytes, R3/bytes>> = R2,
    {NTpB,
     PLEB,
     R4} = case AddrVer of
               2 ->
                   {?MIN_NTPB, ?MIN_PLEB, R3};
               MV when MV >= 3 ->
                   {NonceTrailsPerBytes, RV} = bm_types:decode_varint(R3),
                   {ExtraBytes, RV1} = bm_types:decode_varint(RV),
                   {NonceTrailsPerBytes, ExtraBytes, RV1}
           end,
    case Type of
        ?MSG -> 
            <<DRIPE:20/bytes, MsgEnc/big-integer, R5/bytes>> = R4,
            RecOK = 
            if DRIPE == RIPE ->
                   true;
               true ->
                   false
            end;
        ?BROADCAST ->
            <<MsgEnc/big-integer, R5/bytes>> = R4,
            RecOK = true
    end,

    {Message, R6} = bm_types:decode_varbin(R5),
    {AckData, R7} = if Type == ?MSG ->
                           bm_types:decode_varbin(R6);
                       true -> 
                           {ok, R6}
                    end,
    error_logger:info_msg("msg received  ver ~p message ~p ackdata ~p~n",
                          ["MsgVer",
                           Message,
                           AckData]),
    {Sig, R8} = bm_types:decode_varbin(R7),
    SLen = size(Data) - size(R7),
    <<DataSig:SLen/bytes, _/bytes>> = Data,
    PuSK = <<4, PSK/bytes>>,
    SigOK = verify_signature(Type, DataSig, Payload, Sig, PuSK),
    error_logger:info_msg("Receiver: ~p Signature: ~p AddrVer ~p~n",
                          [RecOK,
                           SigOK,
                           AddrVer]),

    if RecOK, SigOK, AddrVer > 0, AVer =< 4 ->
           {Subject, Text, Attachments} = decode_encoding(Message, MsgEnc),
           FRipe = bm_auth:generate_ripe(<<4, PSK/bytes, 4, PEK/bytes>>),
           From = bm_auth:encode_address(AVer, Stream, FRipe),
           PubKey = #pubkey{hash=FRipe,
                            psk=PSK,
                            pek=PEK,
                            ntpb=NTpB,
                            pleb=PLEB,
                            time=bm_types:timestamp()},
           error_logger:info_msg("~p~n", [PubKey]),
           bm_db:insert(pubkey, [PubKey]),
           MR = #message{hash=Hash, 
                         enc=MsgEnc, 
                         from=From, 
                         to=Address, 
                         subject=Subject,
                         folder=incoming,
                         time=calendar:local_time(),
                         ackdata=AckData,
                         status=unread,
                         type=Type,
                         attachments=Attachments,
                         text=Text},
           bm_db:insert(message, [MR]),
           if AckData /= ok ->
                  bm_sender:send_broadcast(bm_message_creator:create_ack(MR));
              true ->
                  ok
           end,
           Callback:received(Hash),
           {next_state,
            inventory,
            State};
       true ->
           {next_state,
            inventory,
            State}
    end;
payload(timeout,  % {{{2
        #state{
           object=?FILECHUNK,
           decrypted=Data,
           keys=ChunkHash,
           callback=Callback
          } = State) ->
    error_logger:info_msg("Saving FileChunk ~p ~n", [ChunkHash]),
    case bm_db:lookup(bm_filechunk, ChunkHash) of
        [#bm_filechunk{data=undefined} = FC] ->
            {Size,
             <<FileHash:64/bytes,
               ChunkPadded/bytes>>} = bm_types:decode_varint(Data),

            <<Chunk:Size/bytes, _/bytes>> = ChunkPadded,
            mnesia:dirty_delete(bm_filechunk, ChunkHash),
            bm_db:insert(bm_filechunk,
                         [FC#bm_filechunk{status=decrypted,
                                          file=FileHash,
                                          size=Size,
                                          time=calendar:universal_time(),
                                          data=Chunk
                                         }]),
            error_logger:info_msg("Saving FileChunk ~p ~n", [FC]),
            bm_attachment_srv:received_chunk(FileHash, ChunkHash),
            Callback:filechunk_received(FileHash, ChunkHash),
            {next_state,
             inventory,
             State};
        O ->
            error_logger:info_msg("Found other ~p ~n", [O]),
            {next_state,
             inventory,
             State}
    end;
payload(timeout,  % {{{2
        State) ->
    {next_state,
     inventory,
     State};
payload(Event, State) ->  % {{{2
    %error_logger:warning_msg("Wrong event ~p in ~p state ~p~n", [Event, State, ?MODULE_STRING]),
    {next_state,
     payload,
     State,
    0}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_fsm receives an event sent using
%% gen_fsm:send_all_state_event/2, this function is called to handle
%% the event.
%%
%% @spec handle_event(Event, StateName, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState}
%% @end
%%--------------------------------------------------------------------
handle_event({callback, Callback}, StateName, State) ->  % {{{2
    {next_state, StateName, State#state{callback=Callback}, 0};
handle_event(_Event, StateName, State) ->  % {{{2
    {next_state, StateName, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_fsm receives an event sent using
%% gen_fsm:sync_send_all_state_event/[2,3], this function is called
%% to handle the event.
%%
%% @spec handle_sync_event(Event, From, StateName, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {reply, Reply, NextStateName, NextState} |
%%                   {reply, Reply, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState} |
%%                   {stop, Reason, Reply, NewState}
%% @end
%%--------------------------------------------------------------------
handle_sync_event(_Event, _From, StateName, State) ->% {{{2
    Reply = ok,
    {reply, Reply, StateName, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_fsm when it receives any
%% message other than a synchronous or asynchronous event
%% (or a system message).
%%
%% @spec handle_info(Info,StateName,State)->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState}
%% @end
%%--------------------------------------------------------------------
handle_info(_Info, StateName, State) ->% {{{2
    {next_state, StateName, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_fsm when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_fsm terminates with
%% Reason. The return value is ignored.
%%
%% @spec terminate(Reason, StateName, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _StateName, _State) ->% {{{2
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, StateName, State, Extra) ->
%%                   {ok, StateName, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, StateName, State, _Extra) ->  % {{{2
    {ok, StateName, State}.

%%%===================================================================
%%% Internal functions  {{{1
%%%===================================================================

-spec verify_signature(Type, Decrypted, Encrypted, Signature, PuSK) -> any() when  % {{{2
      Type :: object_type(),
      Decrypted :: binary(),
      Encrypted :: binary(),
      Signature :: binary(),
      PuSK :: binary().
verify_signature(Type, Decrypted, Encrypted,  Sig, PuSK) ->
    case crypto:verify(ecdsa, sha, Decrypted, Sig, [PuSK, secp256k1]) of
        true -> true;
        false ->
            %file:write_file("./test/data/broadcast_encr.bin", D),
            %file:write_file("./test/data/broadcast_decr.bin", Data),
            <<_:64/integer,
              TT:12/bytes,
              V/integer,
              Stream/integer,
              Rest/bytes>> = Encrypted,

            Tag = if Type == ?BROADCAST, 
                     V == 5 ->
                         <<Ta:32/bytes, _/bytes>> = Rest,
                         Ta;
                     true ->
                         <<>>
                  end,
            DS = <<TT:12/bytes,
                   V/integer,
                   Stream/integer,
                   Tag/bytes,
                   Decrypted/bytes>>,
            crypto:verify(ecdsa,
                          sha,
                          DS,
                          Sig,
                          [PuSK,
                           secp256k1])
    end.

-spec decode_encoding(Message, MsgEnc) -> {Subject, Text, Attachments} when % {{{2
      MsgEnc :: object_type(),
      Message :: binary(),
      Subject :: binary(),
      Text :: binary(),
      Attachments :: [#bm_file{}].
decode_encoding(Message, 1) ->
    {<<>>, Message, []};
decode_encoding(Message, 2) ->
    {match,
     [_,
      Subject,
      Text]} = re:run(Message,
                      "Subject:(.+)\nBody:(.+)$",
                      [
                       {capture, all, binary},
                       firstline,
                       {newline, any},
                       dotall,
                       ungreedy
                      ]),
    {Subject, Text, []};
decode_encoding(Message, 3) ->
    {match,
     [_,
      Subject,
      Text,
      BAttachments]} = re:run(Message,
                              "Subject:(.+)\nBody:(.+)\nAttachments:(.+)$",
                              [
                               {capture, all, binary},
                               firstline,
                               {newline, any},
                               dotall,
                               ungreedy
                              ]),
    Attachments = save_files(BAttachments),
    {Subject, Text, Attachments}.

-spec save_files(binary()) -> [binary()].  % {{{2
save_files(Data) ->
    {Attachments,
     _} = bm_types:decode_list(Data,
                               fun(<<Hash:64/bytes,
                                     A/bytes>>) ->
                                       error_logger:info_msg("File: ~p~n", [A]),
                                       {Name,
                                        R1} = bm_types:decode_varstr(A),
                                       error_logger:info_msg("File: ~p, hash ~p~n", [Name, Hash]),
                                       {Size,
                                        R2} = bm_types:decode_varint(R1),
                                       error_logger:info_msg("File: ~p, size ~p~n", [Name, Size]),
                                       {Chunks,
                                        <<Key:32/bytes, 
                                          R3/bytes>>} = bm_types:decode_list(R2,
                                                                             fun(<<X:64/bytes,
                                                                                   Y/bytes>>) ->
                                                                                     {X, Y}
                                                                             end),
                                       {#bm_file{
                                           hash=Hash,
                                          name=Name,
                                          size=Size,
                                          chunks=Chunks,
                                          key={bm_auth:pubkey(Key), Key},
                                          time=calendar:universal_time()
                                         }, R3}
                               end), 
    bm_db:insert(bm_file, Attachments),
    lists:map(fun(#bm_file{hash=H}) ->
                      H
              end,
              Attachments).
%%
%%
%% @doc Check if TTL valid for object
%%
-spec check_ttl(Time, Type) -> boolean() when  % {{{2
      Time :: non_neg_integer(),
      Type :: object_type().
check_ttl(Time, ?FILECHUNK) ->
    FileChunkTTL = application:get_env(bitmessage, filechunk_ttl, 3600),
    TTL = Time - bm_types:timestamp(),
    TTL < FileChunkTTL + 10800 andalso TTL > -3600;
check_ttl(Time, _Type) ->
    MessageTTL = application:get_env(bitmessage, message_ttl, 2419200),
    TTL = Time - bm_types:timestamp(),
    TTL < MessageTTL + 10800 andalso TTL > -3600.

-spec check_ackdata(binary()) -> boolean().  % {{{2
check_ackdata(Payload) ->
    case bm_db:match(message,
                     #message{ackdata=Payload,
                              folder=sent,
                              status=ackwait,
                              _='_'}) of
        [] ->
            false;
        [ Message ] ->
            error_logger:info_msg("Recv ack: ~p~n", [Message#message.hash]),
            bm_db:insert(message, [Message#message{status=ok}]),
            true
    end.
