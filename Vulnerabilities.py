import re

from jira import JIRAError

from Vulnerability import Vulnerability, TicketStatus
from Severity import Severity

# https://developer.atlassian.com/cloud/jira/platform/rest/v2/api-group-issues/#api-rest-api-2-issue-bulk-post
# fails with no message or issues in response if try more
MAXIMUM_TICKETS_CREATABLE_IN_A_REQUEST = 50

def add_comments_to_vulnerability_with_existing_tickets(jira, jira_tickets_for_this_vuln,
                                                        vuln_name, vulnerability, dry_run):
    vulnerability.ticket_status = TicketStatus.TICKET_EXISTS

    multiple_tickets_exist_for_vulnerabity = len(jira_tickets_for_this_vuln) > 1
    if multiple_tickets_exist_for_vulnerabity:
        print(
            f'WARNING: multiple tickets :{jira_tickets_for_this_vuln} found for {vuln_name}, check if we can consolidate')

    for vuln in jira_tickets_for_this_vuln:
        vulnerability.comment_ticket(jira, vuln['jira_ticket_id'], dry_run)

# wrapper of vulnerabilities
class Vulnerabilities:
    vulnerabilities: dict # map of vulnerability name to Vulnerability object

    def __init__(self):
        self.vulnerabilities = {}

    def append_vulnerability(self, name:str, repo_name:str , severity:Severity, image_pushed_at, image_id):
        if name not in self.vulnerabilities:
            self.vulnerabilities[name] = Vulnerability(name, severity, repo_name, image_pushed_at, image_id)
        else:
            self.vulnerabilities[name].append(severity, repo_name, image_pushed_at, image_id)

        return self

    # vuln scan results is a map of the vuln name e.g CVE-1284 or ALAS- to the vulnerabilty data object
    def process_existing_tickets_and_mark_scanned_vulnerabilities(self, issues, jira, dry_run):
        known_vuln_and_jira_ids = list(
            map(lambda issue: {'summary': issue.fields.summary, 'jira_ticket_id': issue.key}, issues))

        # iterates through all vulnerabilities we found in scan
        for vuln_name, vulnerability in self.vulnerabilities.items():
            jira_tickets_for_scanned_vuln = [
                vuln_name_and_ticket_id for vuln_name_and_ticket_id in known_vuln_and_jira_ids
                if re.search(vuln_name, vuln_name_and_ticket_id['summary'], re.IGNORECASE)
            ]

            jira_tickets_exist_for_scanned_vulnerability = len(jira_tickets_for_scanned_vuln) > 0
            if jira_tickets_exist_for_scanned_vulnerability:
                add_comments_to_vulnerability_with_existing_tickets(jira, jira_tickets_for_scanned_vuln, vuln_name,
                                                                    vulnerability, dry_run)
            else:
                vulnerability.ticket_status = TicketStatus.NO_TICKET

        self.close_existing_tickets_not_in_current_scan_results(known_vuln_and_jira_ids, jira, dry_run)

    def close_existing_tickets_not_in_current_scan_results(self, existing_relevant_vuln_and_jira_ids, jira, dry_run):
        print(f'Current scan found {len(self.vulnerabilities.keys())} vulnerabilities {self.vulnerabilities.keys()}')

        print(f'Existing {len(existing_relevant_vuln_and_jira_ids)} ticketed vulns {[vuln["summary"] for vuln in existing_relevant_vuln_and_jira_ids]}')

        tickets_to_close = [existing_vuln['jira_ticket_id'] for existing_vuln in existing_relevant_vuln_and_jira_ids
                            if not any(vuln_name.upper() in existing_vuln['summary'].upper() for vuln_name in self.vulnerabilities.keys())  # ticket name not in any of the current scan results
                            and (existing_vuln['summary'].upper().lstrip().startswith('CVE') or existing_vuln['summary'].upper().lstrip().startswith('ALAS')) # ticket name is prefixed CVE or ALAS
                            ]

        print(f'Closing {len(tickets_to_close)} tickets no longer found in scan results: {tickets_to_close}')

        if dry_run:
            print('DRY RUN: skipping closing tickets')
            return

        failed_to_close_ticket_ids = []
        for ticket_id in tickets_to_close:
            issue = jira.issue(ticket_id)
            # Some issue states use "Close", others "Close Issue" to get into Closed state, jira transition method unfortunately takes the transition not the desired end state
            # TODO replace with switch case based on ticket's current status
            try:
                jira.transition_issue(issue, 'Close')
            except JIRAError as e:
                print(f'{e} error trying to close {ticket_id} with Close, trying Close Issue')
                try:
                    jira.transition_issue(issue, 'Close Issue')
                except JIRAError as e:
                    failed_to_close_ticket_ids.append(ticket_id)

        if len(failed_to_close_ticket_ids) > 0:
            print(
                f'Failed to close {failed_to_close_ticket_ids}, manually close them or debug script')

    def create_tickets_for_new_vulnerabilities(self, jira, dry_run):
        new_vulnerabilities_as_jira_issue = [
            vulnerability.create_issue() for vulnerability in self.vulnerabilities.values()
            if vulnerability.ticket_status == TicketStatus.NO_TICKET
        ]

        print(f'Creating {len(new_vulnerabilities_as_jira_issue)} new tickets for the following vulnerabilities:')
        print([f"{vuln_dict['summary']}  {self.vulnerabilities[vuln_dict['summary']].severity}" for vuln_dict in new_vulnerabilities_as_jira_issue])

        if dry_run:
            print('DRY RUN: skipping ticket creation')
            return

        if len(new_vulnerabilities_as_jira_issue) == 0:
            print('No new tickets to create.')
            return
        confirm = input("Type 'yes' to proceed with creating these tickets (anything else aborts): ").strip().lower()
        if confirm != 'yes':
            print('Aborting ticket creation (user did not confirm with yes).')
            return

        for start in range(0, len(new_vulnerabilities_as_jira_issue), MAXIMUM_TICKETS_CREATABLE_IN_A_REQUEST ):
            responses = jira.create_issues(new_vulnerabilities_as_jira_issue[start:start + MAXIMUM_TICKETS_CREATABLE_IN_A_REQUEST])
            error_responses = [response for response in responses if response['status'].casefold() == 'Error'.casefold()]
            if len(error_responses) > 0:
                print(f'Failed to create {len(error_responses)} tickets for the following vulnerabilities:')
                print(error_responses)

            for ticket_id in self.get_successful_ticket_ids(responses):
                jira.transition_issue(ticket_id, 'To Ready')

    def get_successful_ticket_ids(self, responses):
        return [response['issue'].key for response in responses if response['status'].casefold() == 'Success'.casefold()]


    def __repr__(self):
        return f'{self.vulnerabilities}'