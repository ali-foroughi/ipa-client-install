# Install & Configure IPA client on Debian 11

This script installs SSSD, krb5 and makes required configuration to join the client to IPA server.


## Requirements:

- Ubuntu or Debian clinet
- Client name
- Client IP
- Domain name used with the IPA


## Usage
Clone this repo on the server you want to join your IPA.
```
git clone git@github.com:ali-foroughi/ipa-client-install.git
```

Navitage to the directory containing the configuration files and replace them with your own:

```
cd ipa-client-install/config_files
```

Run the script:
```
bash ipa-client-install.sh
```
