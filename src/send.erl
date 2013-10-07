-module(send).
-compile([export_all]).

-include_lib("include/bm.hrl").

main([]) ->
    bm_dispatcher:send_message(#message{to = <<"BM-2DBJhZLvR1rwhD6rgzseiedKASEoNVCA6Q">>, 
                                         from =  <<"BM-Gtv1nnCjSyVHnHD8VN4stfJ8sDRFqgMj">>,
                                         subject = <<"Test my letter">>,
                                         text = <<"Hellow world!">>}).
