# Check-Flow


## Introduction
Check Flow is a Python script that utilizes netflow data collected by nfcapd and various libraries such as maxminddb, socket, and whois to check IP addresses against whitelists and blacklists, as well as retrieve information about the organization associated with an IP address. The script is designed to be efficient and easy to use, making it a valuable tool for network administrators and security professionals.

## Features
Check IP addresses against whitelists and blacklists
Retrieve information about the organization associated with an IP address
Utilize netflow data collected by nfcapd
Manage and manipulate lists of IP addresses
Read IPs from files
Check the validity of an IP address

## Usage
The script requires the following libraries to be installed:

- maxminddb
- socket
- whois
- telegram

The script can be run by executing the following command in the terminal:

```
nfcapd -E -w -T all -p 9001 -l /root/nfcapd/ | ./check_flow.py
```

## Classes
The script includes several classes that are used to manage and manipulate lists of IP addresses, read IPs from files, check the validity of an IP address and check the IP addresses against whitelists and blacklists, retrieve information about the organization associated with an IP address.

- List: defines a list of object
- IpList: defines a list of IP addresses
- Whitelist: class that allows us to use more than one whitelist
- Blacklist: class that allows us to use more than one blacklist
- Organization: class that allows us to check IP addresses
- Flow_original: class with only the original data

## Support
If you have any questions or issues with the script, please open an issue on the GitHub repository or contact us directly.

## Contributions
All contributions are welcome. If you would like to contribute, please fork the repository and open a pull request with your changes.

## License
This project is licensed under the MIT License.

## Acknowledgments
This script was inspired by the need to improve the security of networks and protect against malicious IP addresses. We hope it will be a valuable tool for network administrators and security professionals alike.
