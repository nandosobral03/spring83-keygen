# Readme

This is a simple multi-threaded Rust application for generating and validating cryptographic keypairs for the Spring '83 protocol using the `ed25519_dalek` crate. The program generates keypairs until it finds one where the last byte of the public key equals the current year (in hexadecimal) or the previous year. Keys are valid from the beginning of the date specified on it's last 4 bytes until 2 years later. For example, a key ending in 0823 will be valid until 2023-09-01 00:00:00 UTC. 

### Usage
To run this program, use the command:

```bash
cargo run -- [-t <number_of_threads>] [-y <year>]
```
or  
    
```bash	
cargo run --release -- [-t <number_of_threads>] [-y <year>]
```
For a faster execution.

Alternative you can build it and run the executable
    
```bash
cargo build --release
```

The arguments `-t` and `-y` are optional. They are used as follows:

- `-t`: Specifies the number of threads the application will use to generate and validate keypairs. By default, the program uses the number of logical cores available on your machine. For example, use `-t 8` to use eight threads.

- `-y`: Defines the year (in the format "YY") that should match the last byte of the public key. The program defaults to the current year. For instance, use `-y 23` to search for a keypair whose public key ends with hexadecimal 23 or 22. Meaning it might generate a keypair that is not valid yet. (For example, running the program on 07-2023 might generate a keypair ending in 0823, which is not valid until the start of the next month)

## Output

During execution, the program logs the progress of each thread at regular intervals. Once a valid keypair is found, it is written to a file named `keypair.txt` in the current directory. The output file contains the secret and public keys in hexadecimal format. You can use this keypair to interact directly with either the Client or the Server without having to change their format.

If no valid keypair is found after the maximum number of iterations (`MAX_ITER`) has been reached, the threads stop execution. This is very rare as the program runs for 100 million iterations by default. But if it happens, you can simply run the program again with the same arguments to continue the search.

