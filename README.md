# Zelda Artifact

Zelda is a feedback-driven closed-box fuzzing tool designed for detecting web application vulnerabilities, including cross-site scripting (XSS), SQL injection, and command injection vulnerabilities. This artifact contains the source code for Zelda.


## Installation

Zelda has been tested on Ubuntu 22.04. However, since Zelda is implemented in Python, it should work on any operating system with Python installed.

### Option 1: Using Docker (Recommended)

The easiest way to run Zelda is using Docker. This method handles all dependencies automatically.

* Build the Docker image:
```
$ docker build -t zelda .
```

* Run Zelda with Docker:
```
$ docker run --rm zelda python3 main.py --opt fuzz --url [target_url] --login no
```

* For authenticated fuzzing:
```
$ docker run --rm zelda python3 main.py --opt fuzz --url [target_url] --login yes
```

* To access logs or save results, mount a volume:
```
$ docker run --rm -v $(pwd)/logs:/app/fuzz/logs zelda python3 main.py --opt fuzz --url [target_url] --login no
```

### Option 2: Manual Installation

* Download the zip file from the DOI website and unzip the file:
```
$ unzip zelda.zip -d zelda
```
* Ensure **Python 3.8 or above** and **Chrome** are installed. Install Python dependencies:
```
$ pip install -r requirements.txt
```
* If using a conda environment, run:
```
$ conda env create -f zelda.yaml
```
* To run provided benchmarks, install Docker. Docker installation instructions are available [here](https://docs.docker.com/engine/install/). You can access public benchmarks such as DVNA and WackoPicko as follows:
  - Run DVNA Docker:
    ```
    $ docker run --name dvna -p 1004:9090 -d appsecco/dvna:sqlite
    ```
  - Run WackoPicko using Docker:
    ```
    $ docker run -p 8080:80 -it adamdoupe/wackopicko
    ```

## Configuration

You can customize Zelda by editing the `config.ini` file according to your local environment. The configurable options include:
- Zelda base directory
  ```
  base_dir = /home/username/zelda
  ```
- Chrome driver path:
  ```
  chromedriver_path = ../chromedriver
  ```
- Fuzzing timeout:
  ```
  fuzz_timeout = 5
  ```
- Exploration term:
  ```
  exploration = 1
  ```
- Importance term:
  ```
  importance = 0.6
  ```
- Content change term:
  ```
  content_change = 0.1
  ```

## Usage

Execute Zelda on the target web application:
```
$ cd fuzz
$ python3 main.py --opt fuzz --url [target_url] --login [yes/no]
```
For authentication, you can specify your own credentials and login URLs in `fuzz/src/login_credentials.py`

If Zelda is installed correctly, you should see output similar to:
```
Unauthenticated Crawl Status: Running
Current resource pool size: XX
.
.
XSS Attack starts
vulnerability detected: message, payload: XX
SQL Injection Attack starts
Command Execution / Injection Attack starts
.
```
Detailed logs can be found in the `fuzz/logs` directory.

## Reproducing the Evaluation

### Main Experiment

We evaluated seven web fuzzers on 24 benchmark applications:

- Zelda
- Four closed-box web fuzzers:
  - [Burp Suite](https://portswigger.net/burp) (v2023.10.2.4)
  - [Wapiti](https://wapiti.sourceforge.io) (v3.1.5)
  - [BlackWidow](https://github.com/SecuringWeb/BlackWidow)
  - [wfuzz](https://github.com/xmendez/wfuzz)
- Two semi-open-box web fuzzers:
  - [webFuzz](https://github.com/ovanr/webFuzz)
  - [Witcher](https://github.com/sefcom/Witcher)

Run each fuzzer using these commands:

- **Zelda**:
  - Set parameters: Exploration: `1.0`, Importance: `0.6`, Content changes: `0.1`
  - Set timeout to `5` seconds
  - Run Zelda with `5` workers

- **Burp Suite** (Default settings, via GUI)

- **Wapiti** (Default settings):
  ```
  $ ./bin/wapiti -u [target_url] -m "xss","sql","timesql","exec" --scope domain --flush-attacks --flush-session
  ```

- **BlackWidow** (Default settings):
  ```
  $ python3 crawl.py --url [target_url]
  ```

- **wfuzz**:
  - Use your own crawler to identify target URLs and injection points, then run:
    ```
    $ python3 wfuzz-cli.py -w fuzz.txt -d [parameters] [url]
    ```

- **webFuzz**:
  - Instrument applications:
    ```
    $ php src/instrumentor.php --method http --policy node --dir [target_dir]
    ```
  - Run with `5` workers:
    ```
    $ python3 webFuzz.py -w 5 -m [instr_meta file] --driver [geckodriver_path] -vv --request_timeout 100 -r simple [target_url]
    ```

- **Witcher**:
  - Set up each application directory using the Docker environment provided by Witcher.
  - Run command:
    ```
    $ ./run.sh [target_app]/[username] --build
    ```

