# nstp-cert-status-server
## Jack Warren
### Usage
```
Options:
  --ip TEXT           The IP to run on (default 0.0.0.0)
  --port INT          The port to run on (default 22301)
  --allow FILE        Files containing certs to approve; may be provided
                      multiple times
  --deny FILE         Files containing certs to deny; may be provided multiple
                      times
  --certificate FILE  The certificate to include with responses (required)
  --key FILE          The private key for the status server certificate
                      (required)
  -h, --help          Show this message and exit
```

Both the `allow` and `deny` parameters can handle Certificate and CertificateStore protobufs (written to disk, of course).

The program will print the number of certificates it was able to parse upon startup.

#### Docker
From root of project, run:

```
docker build -t nstp-cert-status-server .
```

The `nstp-cert-status-server` container will still need to be passed arguments and files and given access to a port:

```
docker run -v /tmp/:/tmp/ -p 22301:22301/udp nstp-cert-status-server [OPTIONS]
```
#### Native
From root of project, run:

```
./gradlew run [OPTIONS]
```

This will compile and run directly from source. It requires JDK8 and LibSodium to be available on your machine.

If you'd like to produce a `.jar`, run `./gradlew shadowJar` and use `build/libs/nstp-cert-status-server.jar` 