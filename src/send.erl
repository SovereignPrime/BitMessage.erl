-module(send).
-compile([export_all]).

-include_lib("include/bm.hrl").

main(To, From) ->
    %[#privkey{address=Addr}] = bm_db:lookup(privkey, bm_db:first(privkey)),
    bm_dispatcher:send_message(#message{to = To, 
                                         from =  From, %Addr,
                                         subject = <<"Test my letter">>,
                                         text = <<"Hellow world!">>}).
