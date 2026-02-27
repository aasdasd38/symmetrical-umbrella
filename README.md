=== TERMINAL 1 (Server) ===
> python server.py
Server listening on 0.0.0.0:9999
New connection from ('127.0.0.1', 63930)
Registered asd
New connection from ('127.0.0.1', 49976)
Registered aasd

=== TERMINAL 2 (Receiver - aasd) ===
> python receiver.py
Enter your username: aasd
Registered as aasd
Waiting for messages...
[Message from asd]: hi

=== TERMINAL 3 (Sender - asd) ===
> python sender.py
Enter your username: asd
Registered as asd
Enter recipient username: aasd
Enter your message: hi
Message sent.
