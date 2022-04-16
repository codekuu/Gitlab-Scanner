import os
import re
import json
import shutil
import gitlab
import argparse
import subprocess
from settings.logger_pogger import (
    logger,
    log_message,
    configure_logging,
    add_stream_handler,
    remove_stream_handler,
    check_results,
)
from queue import Empty
from pathlib import Path
from multiprocessing import Queue

from mp4ansi import MP4ansi


HOME = "/opt/gitlab-scanner"
MAX_PROCESSES = 20
client = None
access_token = None
branches_to_scan = "all"


def get_parser():
    """return argument parser"""
    parser = argparse.ArgumentParser(
        description="A Python script that wraps the gitleaks tool to enable scanning of multiple gitlab projects in parallel"
    )
    parser.add_argument(
        "--file",
        dest="filename",
        type=str,
        default="",
        required=False,
        help="scan projects contained in the specified file",
    )
    parser.add_argument(
        "--project-id",
        type=str,
        default="",
        required=False,
        help="scan a specific project by id",
    )
    parser.add_argument(
        "--scan-limit",
        type=int,
        dest="limit",
        required=False,
        default=0,
        help="limit numbers of projects to scan (default: 0 = all)",
    )
    parser.add_argument(
        "--group-id",
        type=str,
        required=False,
        help="gitlab Group Id to scan",
    )
    parser.add_argument(
        "--branches",
        type=str,
        required=False,
        help='specify branch(es) to scan. Separate branch names with "|" (default: all)',
    )
    parser.add_argument(
        "--token",
        dest="token",
        type=str,
        required=True,
        help="access-token to authenticate with Gitlab",
    )
    parser.add_argument(
        "--exclude",
        dest="exclude",
        type=str,
        default="",
        required=False,
        help='a regex to match name of projects to exclude from scanning, divide by using "|"',
    )
    parser.add_argument(
        "--include",
        dest="include",
        type=str,
        default="",
        required=False,
        help='a regex to match name of projects to include in scanning, divide by using "|"',
    )
    parser.add_argument(
        "--debug",
        dest="debug",
        action="store_true",
        help="debug gitlab-scanner to a log file which will be named gitlab-scanner_data-and-time.log",
    )

    return parser


def get_client():
    """return instance of Gitlab client"""
    gitlab_base_url = os.getenv("GITLAB_BASE_URL")
    if not gitlab_base_url:
        raise Exception("Could not find the GITLAB_BASE_URL environment variable.")
    return gitlab.Gitlab(url=os.getenv("GITLAB_BASE_URL"), private_token=access_token)


def redact(str_to_redact, items_to_redact):
    """return str_to_redact with items redacted"""
    if items_to_redact:
        for item_to_redact in items_to_redact:
            str_to_redact = str_to_redact.replace(item_to_redact, "***")
    return str_to_redact


def execute_command(command, items_to_redact=None, **kwargs):
    """execute command"""
    command_split = command.split(" ")
    redacted_command = redact(command, items_to_redact)
    log_message(f"executing command: {redacted_command}")
    process = subprocess.run(command_split, capture_output=True, text=True, **kwargs)
    log_message(
        f"executed command: {redacted_command}' returncode: {process.returncode}"
    )
    if process.stdout:
        log_message(f"stdout:\n{process.stdout}")
    if process.stderr:
        log_message(f"stderr:\n{process.stderr}")
    return process


def get_project_data(clone_urls):
    """return list of project data from clone_urls"""
    projects = []
    for clone_url in clone_urls:
        owner = clone_url.split("/")[3]
        name = clone_url.split("/")[-1].replace(".git", "")
        item = {"clone_url": clone_url, "full_name": f"{owner}/{name}"}
        projects.append(item)
    return projects


def create_dirs():
    """create and return required directories"""
    scans_dir = f"{os.getenv('PWD', HOME)}/scans"
    dirs = {
        "scans": scans_dir,
        "clones": f"{scans_dir}/clones",
    }
    for _, value in dirs.items():
        Path(value).mkdir(parents=True, exist_ok=True)
    return dirs


def get_leak_count(filename):
    """return number of items read in from filename"""
    with open(filename) as infile:
        data = json.load(infile)
    return len(data)


def get_scan_result(branch_name, exit_code, projectrt):
    """return dictionary representing scan result"""
    result = {"branch": branch_name, "leaks": False, "leak_count": 0, "projectrt": "NA"}
    if exit_code != 0:
        result["leaks"] = True
        result["leak_count"] = get_leak_count(projectrt)
        result["projectrt"] = projectrt.replace(os.getenv("PWD", HOME), ".")
    return result


def get_branches(clone_dir):
    """return list of branches from clone_dir
    clone_dir should be a git projectsitory
    """
    logger.debug(f"getting branches from: {clone_dir}")
    process = execute_command("git branch -a", cwd=clone_dir)
    if process.returncode != 0:
        raise Exception("unable to get branches")
    branches = []
    stdout_lines = process.stdout.strip().split("\n")
    for line in stdout_lines:
        regex = "^.*origin/(?P<name>.*)$"
        match = re.match(regex, line)
        if match:
            branch_name = match.group("name")
            if branch_name not in branches:
                if branches_to_scan != "all":
                    if branch_name.lower() not in branches_to_scan.lower().split("|"):
                        continue
                branches.append(branch_name)
    return branches


def scan_project(process_data, *args):
    """execute gitleaks scan on all branches of project"""
    project_clone_url = process_data["clone_url"]
    project_full_name = process_data["full_name"]
    project_name = project_full_name.replace("/", "|")

    log_message(f"scanning item {project_full_name}")

    dirs = create_dirs()
    clone_dir = f"{dirs['clones']}/{project_name}"
    shutil.rmtree(clone_dir, ignore_errors=True)
    project_clone_url = project_clone_url.replace(
        "https://", f"https://oauth2:{access_token}@"
    )
    execute_command(
        f"git clone {project_clone_url} {project_name}",
        items_to_redact=[access_token],
        cwd=dirs["clones"],
    )

    branches = get_branches(clone_dir)
    logger.debug(branches)
    log_message(
        f"executing {len(branches) * 2} commands to scan project {project_full_name}"
    )

    results = []
    for branch_name in branches:
        branch_full_name = f"{project_full_name}@{branch_name}"
        safe_branch_full_name = branch_full_name.replace("/", "|")
        log_message(f"scanning branch {branch_full_name}")
        execute_command(f"git checkout {branch_name}", cwd=clone_dir)
        projectrt = f"{dirs['scans']}/{safe_branch_full_name}.json"
        process = execute_command(
            f"gitleaks detect --source . --report-format json --report-path {projectrt}",
            cwd=clone_dir,
        )
        results.append(get_scan_result(branch_full_name, process.returncode, projectrt))
        log_message(f"scanning of branch {branch_full_name} complete")

    # Delete project when done.
    shutil.rmtree(clone_dir, ignore_errors=True)
    log_message(f"removing project {project_full_name}")
    log_message(f"scanning of project {project_full_name} complete")
    return results


def scan_project_queue(process_data, *args):
    """execute gitleaks scan on all branches of project pulled from queue"""
    project_queue = process_data["item_queue"]
    queue_size = process_data["queue_size"]

    dirs = create_dirs()
    zfill = len(str(queue_size))
    results = []
    project_count = 0
    while True:
        try:
            project = project_queue.get(timeout=6)
            # reset progress bar for next project
            log_message("RESET")
            project_clone_url = project["clone_url"]
            project_full_name = project["full_name"]
            safe_project_full_name = project_full_name.replace("/", "|")

            log_message(
                f"scanning item [{str(project_count).zfill(zfill)}] {project_full_name}"
            )

            clone_dir = f"{dirs['clones']}/{safe_project_full_name}"
            shutil.rmtree(clone_dir, ignore_errors=True)
            project_clone_url = project_clone_url.replace(
                "https://", f"https://oauth2:{access_token}@"
            )
            execute_command(
                f"git clone {project_clone_url} {safe_project_full_name}",
                items_to_redact=[access_token],
                cwd=dirs["clones"],
            )

            branches = get_branches(clone_dir)
            log_message(
                f"executing {len(branches) * 2} commands to scan project {project_full_name}"
            )

            for branch_name in branches:
                # If branch is defined skip all others.
                branch_full_name = f"{project_full_name}@{branch_name}"
                safe_branch_full_name = branch_full_name.replace("/", "|")
                log_message(f"scanning branch {branch_full_name}")
                execute_command(f"git checkout {branch_name}", cwd=clone_dir)
                projectrt = f"{dirs['scans']}/{safe_branch_full_name}.json"
                process = execute_command(
                    f"gitleaks detect --source . --report-format json --report-path {projectrt}",
                    cwd=clone_dir,
                )
                results.append(
                    get_scan_result(branch_full_name, process.returncode, projectrt)
                )
                log_message(f"scanning of branch {branch_full_name} complete")
            # Delete project when done.
            shutil.rmtree(clone_dir, ignore_errors=True)
            log_message(f"removing project {project_full_name}")
            log_message(f"scanning of project {project_full_name} complete")
            project_count += 1
            log_message(f"scanning item [{str(project_count).zfill(zfill)}]")

        except Empty:
            log_message("project queue is empty")
            break

    log_message(
        f"scanning complete - scanned {str(project_count).zfill(zfill)} projects"
    )
    return results


def get_results(process_data):
    """return results from process data"""
    results = []
    for process in process_data:
        try:
            results.extend(process["result"])
        except Exception:
            log_message(f"Process Failed: {process}", info=False)
    return results


def get_process_data_queue(items):
    """get process data for queue processing"""
    item_queue = Queue()
    for item in items:
        item_queue.put(item)
    process_data = []
    for _ in range(MAX_PROCESSES):
        process_data.append(
            {"item_queue": item_queue, "queue_size": item_queue.qsize()}
        )
    return process_data


def execute_scans(items):
    """execute scans for projectos using multiprocessing"""
    if not items:
        raise ValueError("no reopos to scan")

    arguments = {}
    if len(items) <= MAX_PROCESSES:
        arguments["function"] = scan_project
        arguments["process_data"] = items
    else:
        arguments["function"] = scan_project_queue
        arguments["process_data"] = get_process_data_queue(items)

    arguments["config"] = {
        "id_regex": r"^scanning item (?P<value>.*)$",
        "progress_bar": {
            "total": r"^executing (?P<value>\d+) commands to scan .*$",
            "count_regex": r"^executed command: (?P<value>.*)$",
            "max_digits": 2,
        },
    }
    mp4ansi = MP4ansi(**arguments)
    try:
        mp4ansi.execute(raise_if_error=True)
    except Exception as error:
        log_message(f"One or more checks failed: {error}", info=True)
    return get_results(mp4ansi.process_data)


def get_file_projects(filename, limit):
    """return projects read from filename"""
    log_message(f"retrieving projects from file '{filename}'", info=True)
    if not os.access(filename, os.R_OK):
        raise ValueError(f"projects file '{filename}' cannot be read")
    with open(filename) as infile:
        clone_urls = [line.strip() for line in infile.readlines()]
    if limit:
        clone_urls = clone_urls[0:limit]
    projects = get_project_data(clone_urls)
    log_message(
        f"{len(projects)} projects were retrieved from file '{filename}'", info=True
    )
    return projects


def get_project(project_id):
    """return a project from project id"""

    log_message(f"retrieving information about Project Id {project_id}", info=True)
    project = client.projects.get(project_id)
    log_message(f"Project found! Parsing {project.name}...", info=True)

    # Return a list with a dict instead of a dict object.
    projects_fixed = []
    projects_fixed.append(
        {"clone_url": project.http_url_to_repo, "full_name": project.path}
    )

    log_message(f"Parsing done for {project.path}", info=True)

    return projects_fixed


def get_group_projects(group_id, limit):
    """return projects for A specific group id"""

    log_message(f"retrieving information about Group Id {group_id}", info=True)
    group = client.groups.get(group_id)
    log_message(f"Group found! Retrieving all projects for {group.name}...", info=True)
    projects = group.projects.list(all=True, visibility="private", archived=False)

    # Convert to normal list
    projects = projects

    # Buils a dict of each GroupProjects with relevant data.
    projects_fixed = []
    for project in projects:
        projects_fixed.append(
            {"clone_url": project.http_url_to_repo, "full_name": project.path}
        )

    # Limit projects
    if limit:
        projects_fixed = projects_fixed[0:limit]

    log_message(
        f"{len(projects)} projects were retrieved from '{group.name}'", info=True
    )
    return projects_fixed


def get_projects(filename, group_id, project_id, limit):
    """Get projects from filename or group or individual project id"""
    if filename:
        return get_file_projects(filename, limit)
    elif group_id:
        return get_group_projects(group_id, limit)
    elif project_id:
        return get_project(project_id)
    else:
        raise Exception("Need filename, group id or project id to continue.")


def match_criteria(name, include, exclude):
    """return tuple match include and exclude on name"""
    match_include = True
    match_exclude = False
    if include:
        match_include = re.match(include, name)
    if exclude:
        match_exclude = re.match(exclude, name)
    return match_include, match_exclude


def get_matched(items, include, exclude, item_type):
    """return matched items using include and exclude regex"""
    log_message(
        f"filtering {item_type} using include '{include}' and exclude '{exclude}' criteria"
    )
    matched = []
    for item in items:
        match_include, match_exclude = match_criteria(
            item["full_name"], include, exclude
        )
        if match_include and not match_exclude:
            matched.append(item)
    log_message(
        f"{len(matched)} {item_type} remain after applying inclusion/exclusion filters",
        info=True,
    )
    return matched


def match_items(items, include, exclude, item_type):
    """match items using include and exclude regex"""
    if not include and not exclude:
        return items
    return get_matched(items, include, exclude, item_type)


if __name__ == "__main__":

    # Parse arguments
    args = get_parser().parse_args()

    # Configure logging
    configure_logging(args.debug)

    # Add Stream Handler
    stream_handler = add_stream_handler()

    # General Checks
    if not args.filename and not args.group_id and not args.project_id:
        raise Exception("Need file with projects or a group id to perform the scan.")
    if not args.token:
        raise Exception("Gitlab Scanner requires access token to continue.")
    if args.limit:
        log_message(f"Limiting number of scans to {args.limit} projects.", info=True)
    if args.branches:
        branches_to_scan = args.branches
    access_token = args.token

    # Connect to gitlab.
    client = get_client()

    # Fetch and parse projects
    projects = get_projects(args.filename, args.group_id, args.project_id, args.limit)

    # Filter projects
    matched_projects = match_items(projects, args.include, args.exclude, "projects")

    # Strem handler
    remove_stream_handler(stream_handler)

    # Execute all scans
    results = execute_scans(matched_projects)

    # Stream handler
    add_stream_handler(stream_handler=stream_handler)

    # Remove Clones folder (cleanup)
    dirs = create_dirs()
    shutil.rmtree(dirs["clones"], ignore_errors=True)

    # Create CSV file, print information (last steps)
    check_results(results)
