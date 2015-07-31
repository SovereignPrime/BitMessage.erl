-define(MAGIC, 16#e9, 16#be, 16#b4, 16#d9).
-define(ADDR_PREFIX, "BM-").

%% POW constants
-define(MIN_NTPB, 1000).
-define(MIN_PLEB, 1000).

%% @doc Binary message type
-type message_bin() :: binary().

%% @doc object types
-define(GET_PUBKEY, 0).
-define(PUBKEY, 1).
-define(MSG, 2).
-define(BROADCAST, 3).
-define(FILECHUNK, 4).
-define(GETFILECHUNK, 5).
-define(GETFILE, 6).

-type object_type() :: ?GET_PUBKEY
                     | ?PUBKEY
                     | ?MSG
                     | ?BROADCAST
                     | ?FILECHUNK
                     | ?GETFILECHUNK
                     | ?GETFILE
                     | non_neg_integer().

%% @doc Network address storing structure
-record(network_address,
        {
         ip={127, 0, 0, 1} :: inet:ip_address() | atom(),
         port=8444 ::inet:port_number() | atom(),
         time :: bm_types:timestamp() | atom(),
         stream=1 :: integer() | atom(),
         services=1 :: integer() | atom() 
        }).

%% @doc Decoded bitmessage address structure
-record(address,
        {
         version :: integer(),
         stream=1 :: integer(),
         ripe :: binary()
        }).

%% Inventory structure
-record(inventory,
        {
         hash ::binary() | atom(),
         stream=1 :: integer() | atom(),
         payload :: binary() | atom(),
         type :: object_type() | atom(),
         time :: bm_types:timestamp() | atom()
        }).

%% Public Key storing structure
-record(pubkey,
        {
         hash :: binary() | atom(),
         data :: binary() | atom(), % Seems useless
         psk :: binary() | atom(),
         pek :: binary() | atom(),
         used=false :: boolean() | atom(),
         time :: bm_types:timestamp() | atom(),
         ntpb=1000 :: non_neg_integer() | atom(),
         pleb=1000 :: non_neg_integer() | atom()
        }).

%% Private Keys storing structure
-record(privkey,
        {hash :: binary(),
         enabled=true :: boolean(),
         label :: any(),
         address :: binary() | atom(),  % ???
         psk :: binary(),
         pek :: binary(),
         time :: bm_types:timestamp(),
         public :: binary()
        }).

%% Messages and broadcasts storing structure
-record(message,
        {
         hash :: binary() | atom(),
         to :: binary() | atom(),
         from :: binary() | atom(),
         subject :: binary() | atom(),
         enc=2 :: integer() | atom(),
         folder :: string() | atom(),  % ???
         text :: binary() | atom(),
         status=new :: atom(),  % Variants
         ackdata :: binary() | atom(),
         payload :: binary() | atom(),
         type :: object_type() | atom(),
         time :: calendar:date_time() | non_neg_integer(),
         attachments = [] :: [string()] | atom()
        }).


%% Record for file (draft)
-record(bm_file,
        {
         hash :: binary() | atom(),
         name :: iodata() | atom(),
         path :: string() | atom(),
         size :: non_neg_integer() | atom(),
         tarsize=undefined :: non_neg_integer() | atom(),
         chunks :: list(binary()) | atom(), %% ???
         key :: {binary(), binary()} | atom(),
         time :: calendar:date_time() | non_neg_integer(),
         status=received :: atom()
        }).

%% Record for filechunk (draft)
-record(bm_filechunk,
        {
         hash :: binary() | atom(),
         offset :: non_neg_integer() | atom(),
         size :: non_neg_integer() | atom(),
         data :: binary() | atom(),
         file :: binary() | atom(),
         time :: calendar:date_time() | non_neg_integer(),
         payload :: binary() | atom(),
         status=new :: atom()
        }).
         
-type type_record() :: #message{}
                    | #pubkey{}
                    | #privkey{}
                    | #inventory{}
                    | #bm_file{}
                    | #bm_filechunk{}
                    | #network_address{}.
