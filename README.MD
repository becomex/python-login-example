# Becomex Login with Python example

This code sample aims to demonstrate how to perform Becomex's API authentication and consume data from Takeout API. The autentication uses the [OAuth2 authorization flow](https://github.com/becomex/java-login-example#authorization-flow).

## Requirements

Becomex provides a set of API's for exchanging information with clients, in order to guarantee confidentiality, the OAuth2 authentication standard is used (approved by the OpenID Foundation) using the JWT (Json Web Token) model using the public and toilet. In addition, all communication is done using SSL/TLS to ensure an adequate level of security in data transmission.

After creating the key pair, the user must store the private key securely and forward the public key to the Becomex consultant, to be added to the key repository. After the addition, the user will be informed of the `client-id` used to complete the authentication process.

The subsequent steps detail how to proceed to generate the keys and obtain the authentication token.

1. Create a `pass.txt` text file containing the password.
2. Generate the private key using the command:

```sh
openssl genpkey -out privkey.pem -outform PEM -pass file:pass.txt -algorithm RSA -aes-256-cbc -pkeyopt rsa_keygen_bits:4096
```

3. Extract the public key from the private key:

```sh
openssl rsa -in privkey.pem -outform PEM -pubout -out pubkey.pub -passin file:pass.txt
```

See [requirements](./requirements.txt) for more info.

## Build and Run

The project was created with Python version 3.10 and PIP version 22.2.2. To run this project, install the dependencies with PIP:

```sh
pip install -r requirements.txt
```

Then you can run the `main.py` with the command:

```sh
python main.py \
     -c '<client-id>' \
     -k '<private-key-path>' \
     -p '<passphrase>' \
     -t '1' \
     -s 'TB_DI' \
     -d '2022-10-07' \
     -e '2022-10-08' \
     -r '10' \
     -g '1'
```

For more information about the options:

```sh
python main.py -h
```
