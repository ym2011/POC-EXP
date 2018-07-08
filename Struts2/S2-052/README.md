### Description

Apache Struts RCE tool for CVE 2017-9805

### Options

- `u`: the target url;
- `c`: the command that'll be executed on a vulnerable target;
- `f`: automatically checks for RCE using a list of targets (one target per line);
- `p`: specify the port for a local listener - used with `f` option - (default: 8080)

### Usage

```
go run main.go -u target -c command
```

```
go run main.go -f filename
```

```
go run main.go -f filename -p port
```