## zipcrack

`zipcrack` attempts to find the encryption password for a ZIP file with brute force.

`zipcrack` is a hobby project and is not particularly polished. It was tested only with ZIP files created with Ubuntu's `file-roller` tool. Also, while it does its job quite efficiently, the brute force approach will never be as fast as an approach that takes advantage of the ZIP encryption format's vulnerabilities.

Current help text:

```
zipcrack 0.1.0
Attempts to crack a ZIP archive's password with brute force.

USAGE:
    zipcrack [FLAGS] [OPTIONS] <input> --alphabet <alphabet>

FLAGS:
    -h, --help                    Prints help information
        --show-zipfile-records    Prints out the records inside the ZIP file
        --unroll                  Uses the unrolled version of the algorithm
    -V, --version                 Prints version information

OPTIONS:
    -a, --alphabet <alphabet>                The alphabet to build passwords from. Can be "base64" or "custom:<letters>"
        --logfile <logfile>                  Logfile where progress is saved [default: zipcrack_log.json]
        --max-length <max-length>            The maximum password length [default: 10]
        --min-length <min-length>            The minimum password length [default: 1]
        --num-threads <num-threads>          How many threads to spawn [default: 1]
        --start-password <start-password>    Starts the search from this string, not the alphabetically lowest password

ARGS:
    <input>    Input ZIP file. Should contain several files to eliminate false positives
```
