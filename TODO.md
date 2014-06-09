TODO
====

Stability enhancement
---------------------

1. Write tests everywhere they are needed
2. Add specs and Dializer 
3. Code documentation (add comments where they are needed, but not present)
4. Travis configure to full build, dializer and test runnuing

5. Move connection process from dispatcher to receivers to make reconnection more
    stable
6. Improve incomming connections handling and UPnP (critical for retranslation nodes)

Functionality enhancement
-------------------------

1. Add broadcast sending
2. Add callbacks for different not critical, but usefull events
3. Probably make `message` table from `sent` and `incoming`

