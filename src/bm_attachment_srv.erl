-module(bm_attachment_srv).

-behaviour(gen_server).
-include("../include/bm.hrl").

%% API functions  {{{1
-export([
         start_link/2, 
         send_file/1,
         send_chunk/2,
         send_chunk/3,
         progress/1,
         received_chunk/2, 
         create_tar_from_path/1,
         compute_chunk_size/1
        ]).

%% gen_server callbacks  {{{1
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-record(state, {
          callback=bitmessage :: module(),
          file :: #bm_file{},
          path="" :: string(),
          fd :: file:io_device(),
          chunks :: [binary()],
          remaining :: [{non_neg_integer(), non_neg_integer()}],
          timeout=100 :: non_neg_integer()
         }).

%%%===================================================================
%%% API functions   {{{1
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link(Hash, Path) ->   % {{{2
    gen_server:start_link(?MODULE, [Hash, Path], []).
%%
%%--------------------------------------------------------------------
%% @doc
%% Sends file to network
%%
%%--------------------------------------------------------------------
-spec send_file(FileHash) -> ok when  % {{{2
      FileHash :: binary().
send_file(FileHash) ->
    send_chunk(FileHash, 0, 0).

%%--------------------------------------------------------------------
%% @doc
%% Sends filechunk to network
%%
%%--------------------------------------------------------------------
-spec send_chunk(FileHash, ChunkHash) -> ok when  % {{{2
      FileHash :: binary(),
      ChunkHash :: binary().
send_chunk(FileHash, ChunkHash) ->
    Timeout = crypto:rand_uniform(0, 300),
    %timer:sleep(Timeout),
    encode_filechunk(FileHash, ChunkHash).

-spec send_chunk(FileHash, Offset, Size) -> ok when  % {{{2
      FileHash :: binary(),
      Offset :: non_neg_integer(),
      Size :: non_neg_integer().
send_chunk(FileHash, Offset, Size) ->
    %Timeout = crypto:rand_uniform(0, 300),
    %timer:sleep(Timeout),
    case create_tar_from_file(FileHash) of
        {ok, TarPath, _} ->
            Length = case Size of
                         0 ->
                             filelib:file_size(TarPath);
                         _ ->
                             Size
                     end,
            ChunkSize = compute_chunk_size(Length),
            Chunks = bm_types:shuffle(
                       lists:seq(Offset, 
                                 Offset + Length,
                                 ChunkSize)),
            error_logger:info_msg("Chunks number: ~p", [Chunks]),
            spawn_link(
              fun() ->
                      lists:foreach(
                        fun(Location) ->
                                create_filechunk_from_tar(
                                  #bm_filechunk{offset=Location,
                                                size=ChunkSize,
                                                file=FileHash},
                                  TarPath)
                        end,
                        Chunks)
                       end);
        no_file ->
            ok
    end.

-spec progress(FileHash) -> float() when  % {{{2
      FileHash :: binary().
progress(FileHash) ->
    try bm_db:lookup(bm_file, FileHash) of
        [#bm_file{hash=FileHash,
                  tarsize=All}] ->
            Chunks = bm_db:match(bm_filechunk, #bm_filechunk{file=FileHash, _='_'}),
            Here = lists:foldl(fun(#bm_filechunk{size=S}, Acc) ->
                                       Acc + S
                               end,
                               0.0,
                               Chunks),
            Here / All;
        _ ->
            0.0
    catch
        error:_ ->
            0.0
    end.

-spec received_chunk(FileHash, ChunkHash) -> ok when  % {{{2
      FileHash :: binary(),
      ChunkHash :: binary().
received_chunk(FileHash, ChunkHash) -> 
    Pids = supervisor:which_children(bm_attachment_sup),
    error_logger:info_msg("Chunks received for pids ~p", [Pids]),
    send_all(Pids, {received, FileHash, ChunkHash}).

%%%===================================================================
%%% gen_server callbacks {{{1
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
init([Hash, Path]) ->   % {{{2
    Timeout = application:get_env(bitmessage, chunk_timeout, 15) * 60000,
    case bm_db:lookup(bm_file, Hash) of
        [#bm_file{
            status=downloaded,
            name=Name,
            path=OPath
           } = File] ->
            FPath = OPath ++ "/" ++ Name,
            IsFile = filelib:is_file(FPath),
            if IsFile ->
                   error_logger:info_msg("File ~p is here", [FPath]),
                   file:copy(FPath, Path ++ "/" ++ Name),
                   bitmessage:downloaded(Hash),
                   {stop, normal};
               true ->
                   error_logger:info_msg("File ~p is not here", [Name]),
                   download(Path, File, Timeout)
            end;
        [File] ->
            download(Path, File, Timeout)
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
handle_call(_Request, _From, State) ->   % {{{2
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
handle_cast({received, FileHash, ChunkHash},   % {{{2
            #state{
               file=#bm_file{hash=FileHash,
                             size=FileSize,
                             tarsize=TarSize},
               fd=F,
               remaining=Remaining,
               timeout=Timeout
              }=State) ->
    error_logger:info_msg("Chunks received"),
    case bm_db:lookup(bm_filechunk, ChunkHash) of
        [#bm_filechunk{offset=Offset,
                       data=Data,
                       size=Size}] ->
            error_logger:info_msg("Remaining: ~p", [Remaining]),
            file:pwrite(F, Offset, Data),
            NRemaining = lists:foldr(fun({0, 0}, A) -> A;
                                         ({S, E}=T,
                                         [{NS, NE}|R] = A) when E+1 < NS ->
                                             [T | A];
                                        ({S, E}=T,
                                         [{NS, NE}=C|R] = A) when S > NE+1 ->
                                              [C, T | R];
                                        ({S, E}=T,
                                         [{NS, NE}|R] = A) when S < NS,
                                                                E >= NS ->
                                             [{S, NE}|R];
                                        ({S, E}=T,
                                         [{NS, NE}=C|R] = A) when S > NS,
                                                                NE >= S ->
                                             [{NS, E}|R];
                                        (_, A) -> A
                                     end,
                                     [{Offset, Offset + Size}],
                                     Remaining),
            error_logger:info_msg("NRemaining: ~p", [NRemaining]),
            error_logger:info_msg("TarSize: ~p", [TarSize]),
            error_logger:info_msg("FileSize: ~p", [FileSize]),
            if NRemaining == [{0, TarSize}] ->
                   error_logger:info_msg("~p chunks remaining", [0]),
                   {noreply, State#state{remaining=NRemaining}, 0};
               true ->
                   Here = progress(FileHash),
                   error_logger:info_msg("~p chunks downloaded", [Here]),
                   {noreply, State#state{remaining=NRemaining}, Timeout}
            end;
        _ ->
            {noreply, State, Timeout}
    end;
handle_cast(Msg, State) ->   % {{{2
    error_logger:warning_msg("Wrong msg ~p  received in ~p", [Msg, ?MODULE_STRING]),
    {noreply, State, 0}.

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
handle_info(timeout,   % {{{2
            #state{
               file=#bm_file{hash=FileHash},
               timeout=Timeout,
               remaining=[{0, 0}]
                  } = State) ->
    error_logger:info_msg("Timeout file ~p not started yet requesting", [FileHash]),
    bm_sender:send_broadcast(bm_message_creator:create_getfile(FileHash)),
    {noreply, State, Timeout};
handle_info(timeout,   % {{{2
            #state{
               file=#bm_file{tarsize=TarSize}=File,
               path=Path,
               remaining=[{0, TarSize}]
                  } = State) ->
    error_logger:info_msg("Timeout in download: ~p", [TarSize]),
    save_file(File, Path),
    bitmessage:downloaded(File#bm_file.hash),
    {stop, normal, State};
handle_info(timeout,   % {{{2
            #state{
               file=#bm_file{hash=FHash},
               timeout=Timeout,
               remaining=Chunks
                  } = State) ->
    {[0|Starts], Ends} = lists:unzip(Chunks),
    Requests = lists:zip(lists:droplast(Ends), Starts),
    error_logger:info_msg("Timeout file ~p not downloaded yet requesting ~p",
                          [FHash, Requests]),
    lists:foreach(fun({S,E}) ->
                          send_chunk_request(FHash, S, E - S)
                  end,
                  Requests),
    {noreply, State, Timeout};
handle_info(Info, #state{timeout=Timeout} = State) ->
    error_logger:warning_msg("Wrong event in ~p: ~p state ~p~n",
                             [?MODULE_STRING,
                              Info,
                              State]),

    {noreply, State, Timeout}.

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
terminate(_Reason, #state{fd=F}=State) ->   % {{{2
    file:close(F),
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->   % {{{2
    {ok, State}.

%%%===================================================================
%%% Internal functions   % {{{1
%%%===================================================================
-spec send_chunk_request(FHash, Start, Size) -> ok when  % {{{2
      FHash :: binary(),
      Start :: non_neg_integer(),
      Size :: non_neg_integer().
send_chunk_request(FHash, Start, Size) ->
    bm_sender:send_broadcast(bm_message_creator:create_getchunk(FHash, Start, Size)).

-spec save_file(#bm_file{}, Path) -> 'ok' | 'incomplete' when  % {{{2
      Path :: string().
save_file(#bm_file{
             name=Name,
             hash=Hash,
             chunks=Chunks,
             size=Size
            } = File,
          Path) ->
    FPath = Path ++ "/" ++ Name,
    TarFile = FPath ++ ".rz.tar.gz",
    erl_tar:extract(TarFile, [compressed, {cwd, Path}]),
    RSiaze = filelib:file_size(FPath),
    MercleRoot = bm_auth:mercle_root(Chunks),
    error_logger:info_msg("Saving ~p size ~p(~p)[~p]~n", [FPath, RSiaze, Size, filelib:file_size(TarFile)]),
    if RSiaze == Size,
       MercleRoot == Hash ->
            bm_db:insert(bm_file, [File#bm_file{
                                     status=downloaded
                                    }]),
            ok;
        true ->
            incomplete
    end.

-spec is_filchunk_in_network(ChunkHash) -> boolean() when  % {{{2
      ChunkHash :: binary().
is_filchunk_in_network(ChunkHash) ->
    FileChunkObjs = bm_db:match(inventory, #inventory{type=?FILECHUNK}),
    lists:any(fun(#inventory{payload = <<_:22/bytes,
                                      CH:64/bytes,
                                      _/bytes>>}) when CH == ChunkHash ->
                      true;
                 (_) -> false
              end,
              FileChunkObjs).

-spec encode_filechunk(FileHash, ChunkHash) -> ok when  % {{{2
      FileHash :: binary(),
      ChunkHash :: binary().
encode_filechunk(FileHash, ChunkHash) ->
    case bm_db:lookup(bm_filechunk, ChunkHash) of
        [#bm_filechunk{data=undefined}] ->
            create_filechunk_from_file(FileHash, ChunkHash);
        [] ->
            create_filechunk_from_file(FileHash, ChunkHash);
        [#bm_filechunk{data=Data, 
                       payload=Payload}] when Data /= undefined, 
                                              Payload /= undefined ->
            ok
    end.

-spec download(Path, File, Timeout) -> {ok, #state{}, Timeout} when  % {{{2
      Path :: string(),
      File :: #bm_file{},
      Timeout :: non_neg_integer().
download(Path, #bm_file{
                  hash=FileHash,
                  name=Name,
                  key={_Pub, Priv},
                  chunks=Chunks
               } = File,
         Timeout) ->
    NFile = File#bm_file{
              path=Path,
              status=downloading
             },
    bm_db:insert(bm_file, [NFile]),
    bm_decryptor_sup:add_decryptor(#privkey{pek=Priv}),
    FPath = Path ++ "/" ++ Name,
    TarFile = FPath ++ ".rz.tar.gz",
    {ok, F} = file:open(TarFile, [binary, write]),
    bm_sender:send_broadcast(bm_message_creator:create_getfile(FileHash)),
    error_logger:info_msg("Starting file ~p download", [Name]),
    {ok,
     #state{
        path=Path,
        file=NFile,
        fd=F,
        chunks=Chunks,
        remaining=[{0,0}],
        timeout=Timeout
       }, 
     Timeout}.

-spec create_filechunk_from_file(FileHash, ChunkHash) -> ok when  % {{{2
      FileHash :: binary(),
      ChunkHash :: binary().
create_filechunk_from_file(FileHash, ChunkHash) ->
    case create_tar_from_file(FileHash) of
        {ok, TarPath, #bm_file{chunks=ChunkHashes}} ->
            ChunkSize = compute_chunk_size(TarPath),
            Location = length(lists:takewhile(fun(CH) ->
                                                      CH /= ChunkHash 
                                              end,
                                              ChunkHashes)) * ChunkSize,
            create_filechunk_from_tar(#bm_filechunk{offset=Location,
                                                     size=ChunkSize,
                                                     file=FileHash},
                                       TarPath);
        no_file -> ok
    end.


-spec send_all(PIDs, Msg) -> ok when % {{{2
      PIDs :: [pid()],
      Msg :: term().
send_all([], _Msg) ->
    ok;
send_all([Pid|Rest], Msg) ->
    {_, P, _, _} = Pid,
    error_logger:info_msg("Sending to ~p (self ~p)msgh ~p", [P, self(), Msg]),
    gen_server:cast(P, Msg),
    send_all(Rest, Msg).

-spec compute_chunk_size(Size | Path) -> non_neg_integer() when  % {{{2
      Size :: non_neg_integer(),
      Path :: file:filename_all().
compute_chunk_size(Size) when is_integer(Size) ->  
    MaxChunkSize = application:get_env(bitmessage, max_chunk_size, 260000),
    MinChunkSize = application:get_env(bitmessage, min_chunk_size, 2048),
    MaxChunksNumber = application:get_env(bitmessage, chunks_number, 100),
    if Size =< MinChunkSize ->
               Size + 1;
           Size >= MaxChunkSize * MaxChunksNumber ->
               MaxChunkSize;
           Size div MaxChunksNumber >= MinChunkSize ->
               Size div MaxChunksNumber;
           true ->
               MinChunkSize
        end;
compute_chunk_size(Path) ->  
    Size = filelib:file_size(Path),
    compute_chunk_size(Size).

-spec create_tar_from_file(FileHash) -> {ok, TarPath, #bm_file{}} | no_file when  % {{{2
      FileHash :: binary(),
      TarPath :: file:filename_all().
create_tar_from_file(FileHash) -> 
    case bm_db:lookup(bm_file,
                      FileHash) of
        [#bm_file{path=Path,
                  name=Name
                 }=File] ->
            FPath = Path ++ "/" ++ Name,
            case create_tar_from_path(FPath) of
                {ok, TarPath} -> {ok, TarPath, File};
                _ -> no_file
            end;
        _ -> no_file
    end.

-spec create_tar_from_path(Path) -> ok | no_file when  % {{{2
      Path :: file:filename_all().
create_tar_from_path(Path) ->
    IsFile = filelib:is_file(Path),
    if IsFile ->
           TarPath = Path  ++ ".rz.tar.gz",
           Name = filename:basename(Path),
           case erl_tar:create(TarPath,
                               [{Name, Path}],
                               [compressed]) of 
               ok -> {ok ,TarPath};
               _ -> no_file
           end;
       true -> no_file
    end.

-spec create_filechunk_from_tar(#bm_filechunk{},  % {{{2
                                file:filename_all()) -> ok.
create_filechunk_from_tar(#bm_filechunk{offset=Offset,
                                        size=Size}=FC,
                          TarPath) ->
    error_logger:info_msg("Chunk location: ~p size: ~p~n", [Offset, Size]),
    {ok, F} = file:open(TarPath, [binary, read]),
    case file:pread(F, Offset, Size) of
        {ok, Data} ->
            ChunkHash = bm_auth:dual_sha(Data),
            maybe_send_chunk(FC#bm_filechunk{
                                 hash=ChunkHash,
                                 size=size(Data),
                                 data=Data
                                }),
            file:close(F);
            %file:delete(TarPath);
        _ -> ok
    end.

-spec maybe_send_chunk(#bm_filechunk{}) -> ok.  % {{{2
maybe_send_chunk(#bm_filechunk{hash=ChunkHash}=Filechunk) ->
    InNetwork = is_filchunk_in_network(ChunkHash),
    if InNetwork ->
           ok;
       true ->
            bm_message_encryptor:start_link(Filechunk)
    end.
