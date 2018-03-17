# Connecting to scorebot

1. Connect to the scorebot host using `nc <ip> <port>`.
- *Example:* `nc 10.150.111.10 5187`
2. You will be dropped into the scorebot prompt (`REQ>`).


# Submitting a flag

1. Connect to scorebot.
2. At the `REQ>` prompt, enter your flag in this format `flag:<team token>:<flag>` and submit.
- *Example:* `REQ> flag:d7231cd2-2a2a-11e8-bbbe-573106081bb5:f14g`
- [video example](https://asciinema.org/a/Odpozqeg55DPlLyOaFIaIl7ED)


# Registering for a beacon token

1. Connect to scorebot.
2. At the prompt enter `register:<your handle>,<team token>` and submit it.
- *Example:* `register:th3v0id,d7231cd2-2a2a-11e8-bbbe-573106081bb5`
3. You will receive an ACK response with your beacon token.
- *Example:*`ACK>011cdc3e-2a2c-11e8-aee3-8b489b9d8e49`
- [video example](https://asciinema.org/a/SvAUUkzg1oZqGbPyWHldzJ08p)

# Requesting to open a beacon port

1. Connect to scorebot but connect to the 
2. At the `REQ>` prompt, enter your beacon command in this format `beacon:<team token>:<any port>`.
- *Example:* `beacon:d7231cd2-2a2a-11e8-bbbe-573106081bb5:1337`
- [video example](https://asciinema.org/a/CMDqQ6s8oT7pv0J4vBF8PBJTy)

# Beaconing

1. Connect to scorebot but connect on the requested port, instead.
- *Example:* `nc 10.150.111.10 1337`
2. This time when you connect, there will be no `REQ>` prompt profile. Simply paste the beacon token and hit enter.
- *Example:* `011cdc3e-2a2c-11e8-aee3-8b489b9d8e49`
3. After submitting the beacon token, you should see a message stating it was sent.
- [video example](https://asciinema.org/a/EOsGm3KTIi3NAYuMkQV2APFXg)