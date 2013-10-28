-module(bitmessage).
-compile([export_all]).
-include("../include/bm.hrl").

send_message(From, To, Subject, Text) ->
    bm_dispatcher:send_message(#message{from=From, to=To, subject=Subject, text=Text}).

send_message(From, To, Subject, Text, Encoding) ->
    bm_dispatcher:send_message(#message{from=From, to=To, subject=Subject, text=Text, enc=Encoding}).

send_broadcast(From, Subject, Text, Encoding) ->
    bm_dispatcher:send_broadcast(#message{from=From, subject=Subject, text=Text, enc=Encoding}).

register_resiever(Module) ->
    bm_dispatcher:register_resiever(Module).
