-module(bm_attachment_srv).

-behaviour(gen_server).
-include("../include/bm.hrl").

%% API functions  {{{1
-export([
         start_link/3, 
         send_chunk/3,
         received_chunk/2
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
          chunks :: [binary()],
          remaining :: [binary()],
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
start_link(Hash, Path, Callback) ->   % {{{2
    gen_server:start_link(?MODULE, [Hash, Path, Callback], []).

%%--------------------------------------------------------------------
%% @doc
%% Sends filechunk to network
%%
%%--------------------------------------------------------------------
-spec send_chunk(FileHash, ChunkHash, Callback) -> ok when  % {{{2
      FileHash :: binary(),
      ChunkHash :: binary(),
      Callback :: module().
send_chunk(FileHash, ChunkHash, Callback) ->
    Timeout = crypto:rand_uniform(0, 300),
    timer:sleep(Timeout),
    InNetwork = is_filchunk_in_network(ChunkHash),
    if InNetwork ->
           ok;
       true ->
           encode_filechunk(FileHash, ChunkHash, Callback)
    end.

-spec received_chunk(FileHash, ChunkHash) -> ok when  % {{{2
      FileHash :: binary(),
      ChunkHash :: binary().
received_chunk(FileHash, ChunkHash) -> 
    gen_server:cast(?MODULE, {received, FileHash, ChunkHash}).

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
init([Hash, Path, Callback]) ->   % {{{2
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
                   Callback:downloaded(Hash),
                   {stop, normal};
               true ->
                   error_logger:info_msg("File ~p is not here", [Name]),
                   download(Path, File, Callback, Timeout)
            end;
        [File] ->
            download(Path, File, Callback, Timeout)
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
               chunks=Chunks,
               timeout=Timeout
              }=State) ->
    error_logger:info_msg("Chunks received"),
    case lists:foldl(fun(CID, Acc) ->
                             case bm_db:lookup(bm_filechunk, CID) of
                                 [] -> 
                                     Acc + 1;
                                 [#bm_filechunk{data=undefined,
                                                hash=CID}] -> 
                                     Acc + 1;
                                 [_] ->
                                     Acc
                             end
                     end,
                     0,
                     Chunks) of
        0 -> 
            error_logger:info_msg("~p chunks remaining", [0]),
            {noreply, State, 0};
        Size ->
            error_logger:info_msg("~p chunks remaining", [Size]),
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
               file=File,
               path=Path,
               chunks=Chunks,
               callback=Callback,
               remaining=[]
                  } = State) ->
    case lists:foldl(fun(CID, Acc) ->
                             case bm_db:lookup(bm_filechunk, CID) of
                                 [] -> 
                                     [CID | Acc];
                                 [#bm_filechunk{data=undefined,
                                                hash=CID}] -> 
                                     [CID | Acc];
                                 [_] ->
                                     Acc
                             end
                     end,
                     [],
                     Chunks) of
        [] ->
            save_file(File, Path),
            Callback:downloaded(File#bm_file.hash),
            {stop, normal, State};
        Remaining ->
            {noreply, State#state{remaining=Remaining}, 0}
    end;
handle_info(timeout,   % {{{2
            #state{
               file=#bm_file{hash=FHash},
               timeout=Timeout,
               remaining=Chunks
                  } = State) ->
    lists:foreach(fun(C) ->
                          send_chunk_request(FHash, C)
                  end,
                  Chunks),
    {noreply, State#state{remaining=[]}, Timeout};
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
terminate(_Reason, _State) ->   % {{{2
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
-spec send_chunk_request(FHash, CID) -> ok when  % {{{2
      FHash :: binary(),
      CID :: binary().
send_chunk_request(FHash, CID) ->
    case bm_db:lookup(bm_filechunk, CID) of
        [#bm_filechunk{data=Data}] when Data /= undefined ->
            ok;
        _ ->
            bm_db:insert(bm_filechunk, [#bm_filechunk{hash=CID, file=FHash}]),
            bm_sender:send_broadcast(bm_message_creator:create_getchunk(FHash, CID))
    end.

-spec save_file(#bm_file{}, Path) -> 'ok' | 'incomplete' when  % {{{2
      Path :: string().
save_file(#bm_file{
             name=Name,
             hash=Hash,
             chunks=Chunks,
             size=Size
            } = File,
          Path) ->
    BChuncks = lists:map(fun(C) ->
                                 [#bm_filechunk{data=BC}] = bm_db:lookup(bm_filechunk,
                                                                         C),
                                 BC
                         end,
                         Chunks),
    TarFile = << <<D/bytes>> || D <- BChuncks>>,

    erl_tar:extract({binary, TarFile}, [compressed, {cwd, Path}]),
    FPath = Path ++ "/" ++ Name,
    file:write_file(FPath ++ ".tar.gz", TarFile),
    RSiaze = filelib:file_size(FPath),
    MercleRoot = bm_auth:mercle_root(Chunks),
    error_logger:info_msg("Saving ~p size ~p(~p)[~p]~n", [FPath, RSiaze, Size, size(TarFile)]),
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

-spec encode_filechunk(FileHash, ChunkHash, Callback) -> ok when  % {{{2
      FileHash :: binary(),
      ChunkHash :: binary(),
      Callback :: module().
encode_filechunk(FileHash, ChunkHash, Callback) ->
    case bm_db:lookup(bm_filechunk, ChunkHash) of
        [#bm_filechunk{data=undefined}] ->
            create_filechunk_from_file(FileHash, ChunkHash, Callback);
        [] ->
            create_filechunk_from_file(FileHash, ChunkHash, Callback);
        [#bm_filechunk{data=Data, 
                       payload=Payload}] when Data /= undefined, 
                                              Payload /= undefined ->
            ok
    end.

-spec download(Path, File, Callback, Timeout) -> {ok, #state{}, Timeout} when  % {{{2
      Path :: string(),
      File :: #bm_file{},
      Callback :: module(),
      Timeout :: non_neg_integer().
download(Path, #bm_file{
                  name=Name,
                  key={_Pub, Priv},
                  chunks=Chunks
               } = File,
         Callback,
         Timeout) ->
    NFile = File#bm_file{
              path=Path,
              status=downloading
             },
    bm_db:insert(bm_file, [NFile]),
    bm_decryptor_sup:add_decryptor(#privkey{pek=Priv}),
    error_logger:info_msg("Starting file ~p download", [Name]),
    {ok,
     #state{
        path=Path,
        file=NFile,
        chunks=Chunks,
        remaining=[],
        callback=Callback,
        timeout=Timeout
       }, 
     0}.

-spec create_filechunk_from_file(FileHash, ChunkHash, Callback) -> ok when  % {{{2
      FileHash :: binary(),
      ChunkHash :: binary(),
      Callback :: module().
create_filechunk_from_file(FileHash, ChunkHash, Callback) ->
    case bm_db:lookup(bm_file,
                      FileHash) of
        [ #bm_file{path=Path,
                   name=Name,
                   chunks=ChunkHashes
                  } ] ->
            ChunkSize = application:get_env(bitmessage, chunk_size, 1024),
            IsFile = filelib:is_file(Path ++ "/" ++ Name),
            if IsFile ->
                   Location = length(lists:takewhile(fun(CH) ->
                                                             CH /= ChunkHash 
                                                     end,
                                                     ChunkHashes)) * ChunkSize,
                   error_logger:info_msg("Chunk location: ~p~n", [Location]),
                   TarPath = Path  ++ ".rz.tar.gz",
                   erl_tar:create(TarPath,
                                  [Path],
                                  [compressed]),
                   {ok, F} = file:open(TarPath, [binary, read]),
                   case file:pread(F, Location, ChunkSize) of
                       {ok, Data} ->
                           bm_message_encryptor:start_link(#bm_filechunk{
                                                              hash=ChunkHash,
                                                              size=size(Data),
                                                              data=Data,
                                                              file=FileHash
                                                             },
                                                           Callback),
                           file:close(F),
                           file:delete(TarPath),
                           ok;
                       _ ->
                           ok
                   end;
               true -> 
                   ok
            end;
        _ -> ok
    end.
