# Prototype vault implementation using keymaker-ui

A prototype app that utilizes the strong password creation feature of [keymaker-ui](https://github.com/apadartha-code/keymaker-ui/tree/main) Flask blueprint to store secrets.

⚠️ **Disclaimers:** This codebase is currently an early-stage academic proof of concept. While the underlying logic functions as intended, the implementation is research-grade, fragile, and not optimized for production environments.

---

## 🚀 Getting Started

**Note**: The app requires a startup password for the UIs to validate. If it is ran non-interactively, it will block till initnonce.sh is ran as shown below.

### Terminal:
#### Prerequisites
* **Python 3.8+** (Ensure this matches your backend requirements)

#### Installation & Execution
```bash
# Clone the repository
git clone https://github.com/apadartha-code/vault-proto.git

# Navigate into the project folder
cd vault-proto

# (Optional) Ensure scripts are executable
chmod +x setup.sh cert.sh

# Set up the virtual environment and the certificates
./setup.sh

# Follow the on-screen instructions to activate the app.
# The admin interface will listen locally on port 5000 (0.0.0.0:5000) over https.
# Ignore the browser warnings for certificate verification and proceed.
```

#### Storage

To persistently store the vault keys and states, a ```data/``` folder will be automatically created (among others) under the main application folder. You should back up this folder periodically if storing actual useful secrets, along with the image(s) needed to generate the vault access passwords.

#### CLI for vault operations

You will need to generate an OTP from the vault management page of admin UI once it has been opened.
```bash
# The following assumes you are in the root folder of the project.
$ source venv/bin/activate
(venv) $ python cli/testclient.py -h
```

```text
usage: testclient.py [-h] [--verify-cert] [-f COMMAND_FILE] hostname port

OTP Authentication and Decryption Client

positional arguments:
  hostname              Target server hostname
  port                  Target server port

optional arguments:
  -h, --help            show this help message and exit
  --verify-cert         Verify SSL certificate (default: False)
  -f COMMAND_FILE, --command-file COMMAND_FILE
                        Run commands line by line from a file.
```

Once you start it with the proper hostname and port, it will block on the OTP from the admin UI. After you provide the OTP, type ```help``` for commands.

### Docker:
#### Prerequisites
* Access to **docker** group for running docker commands.

### Building the image
```bash
# Clone the repository
git clone https://github.com/apadartha-code/vault-proto.git

# Navigate into the project folder
cd vault-proto

# Build the image
docker build -t vault-proto .
```

### Storage

Create a dedicated folder under your $HOME to map to the container for storing vault keys and states. You should back up this folder periodically if storing actual useful secrets, along with the image(s) needed to generate the vault access passwords.

#### Running interactively (password from console)
```bash
# Run the image
export VAULT_HOME=</path/to/vault/state/folder>
docker run -it --rm -p 5000:5000 --name vault -v $VAULT_HOME:/app/data vault-proto

# Set a password to verify the server from the browser.

# The admin interface will listen locally on port 5000 (0.0.0.0:5000) over https.
# Ignore the browser warnings for certificate verification and proceed.
```

#### Running in detached mode (using FIFO)
```bash
# Start the app. It will be blocked on the fifo.
export VAULT_HOME=</path/to/vault/state/folder>
docker run -d --rm -p 5000:5000 --name vault -v $VAULT_HOME:/app/data vault-proto  --fifo-path /tmp/vault_fifo

# Provide the startup nonce to unblock the run.
docker exec -it vault /app/initnonce.sh

# Optionally run the CLI (see above for OTP and other details):
docker exec -it vault python /app/cli/testclient.py -h
```
