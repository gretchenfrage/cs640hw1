
## to run

```sh
python3 sender.py [args]
```

```sh
python3 requester.py [args]
```

```sh
python3 emulator.py [args]
```

## notes

The `common` module contains code shared between sender and receiver.

## running demo 3

This assumes all on same host. If on different hosts, modifications to demo
files must be made.

Emulator:

```sh
cd demo-eg3/emulator
python3 ../../emulator.py -p 3000 -q 100 -f table3 -l log03
```

Sender:

```sh
cd demo-eg3/sender
python3 ../../sender.py -p 5000 -g 4000 -r 100 -q 1 -l 10 -f localhost -e 3000 -i 3 -t 1000
```

Requester:

```sh
cd demo-eg3/requester
python3 ../../requester.py -p 4000 -f snares-08 -e 3000 -o file.txt -w 10
```
