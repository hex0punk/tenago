# tenago
A Go API client and command line tool for Tenable.io

## Why?

1) To learn and practice Go
2) There a multiple questions that I cannot answer using the Tenable.io GUI alone. Because of that, this projects consists not just of the API alone but also a command utility that allows users to perform multiple queries that, with the UI interface alone, would require multiple manual steps. 

## Usage
Run the application without argument or use the `-h` flag to get usage information.

```
λ go run main.go
A Tenable API go client with powerful commands
                                        created by Alex Useche
                                        Complete documentation is available at [TBD]

Usage:
  tenago [command]

Available Commands:
  help        Help about any command
  query       Queries assets, scans, target groups and vulnerabilities.
  version     Print the version number of Tenago

Flags:
      --config string   config file (default is the base folder where tenago is located)
  -h, --help            help for tenago
  -v, --verbose         verbose output

Use "tenago [command] --help" for more information about a command.


Use "tenago [command] --help" for more information about a command.

C:\Users\auseche\go\src\github.com\DharmaOfCode\tenago (master -> origin)
```
## Getting Started
Download the binaries from the release page and run. You will need to have a file called `config.yml` in the folder where you have tenago. The file must include the access key and API key for your Tenable.go license. You can copy and paste the below in your `config.yml` file and replace each value accordingly.

```
credentials:
        accessKey: "YourAccessKeyHere"
        secretKey: "YourSecretKeyHere"
```

## Examples

Get a list of all target groups that have host MYAWESOME-HOST:

```
tenago query -T --hostname MYAWESOME-HOST 
```

Get a list of all configured scans with host MYAWESOME-HOST:

```
tenago query -S --hostname MYAWESOME-HOST
```

Show asset details for host MYAWESOME-HOST:

```
tenago query -A --hostname MYAWESOME-HOST
```

Find the hostname for host with IP 192.168.4.4

```
tenago query -A --ip 192.168.4.4
```




