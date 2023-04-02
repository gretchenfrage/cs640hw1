
## to run

```sh
python3 sender.py [args]
```

```sh
python3 requester.py [args]
```

## notes

The `common` module contains code shared between sender and receiver.

## example demo

1. create this directory structure:
    - `demo/`
        - `sender1/`
            - `hello_world.txt`:

              `hello`
        - `sender2/`
            - `hello_world.txt`:

              ` world`
        - `receiver/`
            - `tracker.txt`:

              ```
              hello_world.txt 2 127.0.0.1 3002
              red_herring.txt 3 127.0.0.1 3003
              hello_world.txt 1 127.0.0.1 3001
              ```
2. (let run in background) in `demo/sender1`, run:
   
   ```sh
   python3 ../../sender.py -p 3001 -g 3000 -r 2 -q 0 -l 3
   ```
3. (let run in background) in `demo/sender2`, run:
   
   ```sh
   python3 ../../sender.py -p 3002 -g 3000 -r 2 -q 5 -l 3
   ```
4. in `demo/receiver`, run:
   
   ```sh
   python3 ../../requester.py -p 3000 -o hello_world.txt
   ```

This should successfully do the download. Observed effects:

- `demo/receiver/hello_world.txt`: now contains `hello world`
- output of the sender 1 process:
  
  ```
  DATA Packet
  send time:        2023-03-01 19:31:08.213519
  requester addr:   127.0.0.1:3000
  Sequence num:     0
  length:           3
  payload:          hel
  
  DATA Packet
  send time:        2023-03-01 19:31:08.714056
  requester addr:   127.0.0.1:3000
  Sequence num:     3
  length:           2
  payload:          lo
  
  END Packet
  send time:        2023-03-01 19:31:09.214060
  requester addr:   127.0.0.1:3000
  Sequence num:     5
  length:           0
  payload:          

  ```
- output of the sender 2 process:

  ```
  DATA Packet
  send time:        2023-03-01 19:31:09.214329
  requester addr:   127.0.0.1:3000
  Sequence num:     5
  length:           3
  payload:           wo
  
  DATA Packet
  send time:        2023-03-01 19:31:09.714869
  requester addr:   127.0.0.1:3000
  Sequence num:     8
  length:           3
  payload:          rld
  
  END Packet
  send time:        2023-03-01 19:31:10.214868
  requester addr:   127.0.0.1:3000
  Sequence num:     11
  length:           0
  payload:          

  ```
