import boto3
from jira.client import JIRA
import getpass
import time
from Severity import Severity
from Vulnerabilities import Vulnerabilities
# Setup your ~/.aws/config with the profile with name in format like profile name there
# then `aws-sso-util login`` , then run script from your CLI 

# move this into vulnerabilities class later , pass in the ecr client

DRY_RUN = True

def determine_vulnerabilities(region_name='us-east-1'):
    ecr_client = boto3.client('ecr', region_name=region_name)

    repositories_response = ecr_client.describe_repositories()

    vulnerabilities = Vulnerabilities()

    for repo in repositories_response['repositories']:
        repo_name = repo['repositoryName']

        images_response = ecr_client.describe_images(repositoryName=repo_name)

        latest_image = None
        if len(images_response['imageDetails']) > 0:
            latest_image = max(images_response['imageDetails'], key=lambda x: x['imagePushedAt'])

        if latest_image is None:
            continue

        image_digest = latest_image['imageDigest']

        scan_response = retrieve_image_scan_response(ecr_client, image_digest, repo_name)

        if 'imageScanFindings' in scan_response:
            findings = scan_response['imageScanFindings'].get('findings', [])
            for finding in findings:
                if 'severity' in finding and 'name' in finding:
                    # track latest image seen with issue
                    vulnerabilities.append_vulnerability(finding['name'], repo_name, Severity.from_raw(finding['severity'].upper()), latest_image['imagePushedAt'], image_digest)

    return vulnerabilities


def retrieve_image_scan_response(ecr_client, image_digest, repo_name):
    print(f"Checking scan results in repository: {repo_name}")
    try:
        ecr_client.start_image_scan(repositoryName=repo_name, imageId={'imageDigest': image_digest})
    except Exception as e:  # todo fix direct exception catch
        if e.response['Error']['Code'] in ('LimitExceededException'):
            print(f'LimitExceededException, scan is already fresh for {repo_name} image {image_digest}')
        else:
            print(
                f'Unexpected exception {e} for {repo_name} attempting to scan image {image_digest}, consider doing it manually. Using existing scan results.')
            raise(e)

    scan_response = ecr_client.describe_image_scan_findings(repositoryName=repo_name,
                                                            imageId={'imageDigest': image_digest})
    image_scan_response_completed_at = scan_response['imageScanFindings']['imageScanCompletedAt']

    start_time = time.time()
    INITIAL_DELAY_IN_SECONDS = 2
    MAX_DELAY_IN_SECONDS = 30
    delay = INITIAL_DELAY_IN_SECONDS
    TIMEOUT_IN_SECONDS = 60

    while image_scan_response_completed_at is None:
        scan_response = ecr_client.describe_image_scan_findings(repositoryName=repo_name,
                                                                imageId={'imageDigest': image_digest})
        image_scan_response_completed_at = scan_response['imageScanFindings']['imageScanCompletedAt']

        if time.time() - start_time > TIMEOUT_IN_SECONDS:
            print(f'WARNING: Timed out waiting for fresh scan to complete for {repo_name} image {image_digest}')
            break

        time.sleep(delay)
        delay = min(delay * 2, MAX_DELAY_IN_SECONDS)

    return scan_response


def jira_login():
    email = f"{getpass.getuser()}@email.com"
    token = getpass.getpass("enter jira cloud api token: ")

    options = {
    'server' : 'https://yourThingHere.atlassian.net',
    'rest_api_version': '3'
    }

    jira = JIRA(options=options, basic_auth=(email, token))

    return jira

MAXIMUM_JIRA_SEARCH_RESULTS =50
def retrieve_jira_tickets(jira):
    start_at = 0
    issues = []
    while start_at >= 0:
        # summary (title) search filters do not work as expected to restrict to tickets prefixed with CVE or ALAS only
       search_results = jira.search_issues(jql_str='labels = Vulnerability AND "Epic Link" = <your epic ticket number here> AND status != Closed', startAt=start_at)
       print(f'{len(search_results)} issues retrieved in this batch')
       issues += search_results

       if len(search_results) == MAXIMUM_JIRA_SEARCH_RESULTS:
         start_at += MAXIMUM_JIRA_SEARCH_RESULTS
       else:
         start_at = -1

    print(f'Retrieved {len(issues)} issues from JIRA')
    return issues

if __name__ == "__main__":
    vulnerabilities = determine_vulnerabilities()
    jira = jira_login()
    vulnerabilities.process_existing_tickets_and_mark_scanned_vulnerabilities(retrieve_jira_tickets(jira), jira, DRY_RUN)
    vulnerabilities.create_tickets_for_new_vulnerabilities(jira, DRY_RUN)
    jira.close()

