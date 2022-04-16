# Gitlab Scanner
A Python script that wraps the [gitleaks](https://github.com/zricethezav/gitleaks) tool to enable scanning of multiple repositories in parallel.
Gitlab scanner is based on [mpgitleaks](https://github.com/soda480/mpgitleaks) which is a github secret scanner.

The motivation behind writing this script was:
* implement workaround for `gitleaks` intermittent failures when cloning very large repositories
* implement ability to scan multiple repostiories in parallel
* implement ability to scan repositories for a specific group or read repositories from a file
* implement ci/cd friendliness by exiting exit(1) upon leaks found.

**Notes**:
* the script uses https to clone the repos
  * you must set the `GITLAB_BASE_URL` environment variables - this should be the url to the gitlab which you would like to scan.
  * if using `--file` then https clone urls must be supplied in the file
* Script requires a access-token which can be set by `--token` parameter when running Gitlab-Scanner.
* the maximum number of background processes (workers) that will be started is `20`
  * if the number of repos to process is less than the maximum number of workers
    * the script will start one worker per repository
  * if the number of repos to process is greater than the maximum number of workers
    * the repos will be added to a thread-safe queue and processed by all the workers
* the Docker container must run with a bind mount to the working directory in order to access logs/reports
  * the repos will be cloned to the `./scans/clones` folder in the working directory this folder will be deleted after the script is completed.
  * the reports will be written to the `./scans/` folder in the working directory
  * a summary report will be written to `gitlab-scanner_Resutls_DATE.csv`
  * after each project has been scanned, the repository will be deleted to minimize the storage.


## Usage
```bash
usage: gitlab-scanner.py [-h] [--file FILENAME] [--project-id PROJECT_ID]
                         [--scan-limit LIMIT] [--group-id GROUP_ID]
                         [--branches BRANCHES] --token TOKEN
                         [--exclude EXCLUDE] [--include INCLUDE] [--debug]

A Python script that wraps the gitleaks tool to enable scanning of multiple
gitlab projects in parallel

optional arguments:
  -h, --help            show this help message and exit
  --file FILENAME       scan projects contained in the specified file
  --project-id PROJECT_ID
                        scan a specific project by id
  --scan-limit LIMIT    limit numbers of projects to scan (default: 0 = all)
  --group-id GROUP_ID   gitlab Group Id to scan
  --branches BRANCHES   specify branch(es) to scan. Separate branch names with
                        "|" (default: all)
  --token TOKEN         access-token to authenticate with Gitlab
  --exclude EXCLUDE     a regex to match name of projects to exclude from
                        scanning, divide by using "|"
  --include INCLUDE     a regex to match name of projects to include in
                        scanning, divide by using "|"
  --debug               debug gitlab-scanner to a log file which will be named
                        gitlab-scanner_data-and-time.log
```

## Execution

Build the image:
```bash
docker build -t gitlab-scanner .
```

Execute the Docker container:
```bash
docker container run \
--rm \
-it \
-e GITLAB_BASE_URL="https://some-gitlab-instance.com" \
-v $PWD:/opt/gitlab-scanner \
gitlab-scanner \
OPTIONS (example: --token "xxxx" --group-id 10 --exclude "project-name" --scan-limit 10)
```
Entrypoint in the docker container is gitlab-scanner.py, when running the container pass the options from gitlab-scanner.


### Examples

Scan all repos contained in the file :
```bash
gitlab-scanner --token "xxxx" --file 'some-file-containing-repos.txt' --exclude "project-name1|project-name2|.*ansible.*"
```

Scan all repos for the authenticated user but exclude the repos that match the specified regex:
```bash
gitlab-scanner --token "xxxx" --group-id XX --exclude 'project-name'
```

Scan all repos in the specified organization but only include the repos that match the specified regex:
```bash
gitlab-scanner --token "xxxx" --group-id XX --include '.*-ansible'
```

Scan a specific project via project id but :
```bash
gitlab-scanner --token "xxxx" --project-id XX
```

Scan only the first 10 projects found in group:
```bash
gitlab-scanner --token "xxxx" --group-id XX --scan-limit 10
```

Scan only master, main and staging branches:
```bash
gitlab-scanner --token "xxxx" --group-id XX --branches "master|main|staging"
```
