import csv
from contextlib import contextmanager
import logging
import re
import requests
import sqlite3 as db
from xml.etree.ElementTree import fromstring

logging.basicConfig(level=logging.INFO)

servers = {'US1': 'qualysapi.qualys.com',
           'US2': 'qualysapi.qg2.apps.qualys.com',
           'EU': 'qualysapi.qualys.eu'}


def _post(session, resource, action, data=None):
    data = data or {}
    data['action'] = action
    resp = session.post('https://{}/api/2.0/fo/{}/'.format(servers['US1'], resource), data=data)
    logging.debug(resp)
    return resp


def _get(session, resource, action, params=None):
    logging.debug('GET | {} | {}'.format(action, params))
    params = params or {}
    params['action'] = action
    resp = session.get('https://{}/api/2.0/fo/{}/'.format(servers['US1'], resource), params=params)
    logging.debug(resp)
    return resp


@contextmanager
def connect(username, password):
    """Login to the API server and return session object.

    :param username: The user name (login) of a Qualys user account.
    :param password: The password of a Qualys user account."""
    session = requests.session()
    session.headers.update({'X-Requested-With': 'BXII Client'})
    # Login
    resp = _post(session, 'session', 'login', {'username': username,
                                               'password': password})
    logging.debug(resp)
    session.cookies = resp.cookies
    yield session
    resp = _get(session, 'session', 'logout')
    logging.debug(resp)


def update_db(session, reset=False):
    """Dump the KB database (basic detail level) and update the database.

    :param session: requests Session object.
    :param reset: remove all current records."""
    with db.connect('qualys.db') as conn:
        c = conn.cursor()
        if reset:
            c.execute('DROP TABLE cve_qid')
            logging.info('dropped "cvd_qid" table')
        try:
            c.execute('SELECT max(qid) FROM cve_qid')
            latest_id = int(c.fetchone()[0])
            logging.info('latest QID on database is {}'.format(latest_id))
            data = {'id_min': latest_id + 1}
        except db.Error:
            c.execute('CREATE TABLE cve_qid (cve TEXT UNIQUE, qid INTEGER)')
            logging.info('created "cve_qid" table')
            data = None
        except TypeError:
            logging.info('table is empty')
            data = None
        resp = _post(session, 'knowledge_base/vuln', 'list', data)
        logging.debug(resp)
        root = fromstring(resp.text)
        for vuln in root.iter('VULN'):
            # Every vulnerability has a QID.
            qid = vuln.find('QID').text
            cve_list = vuln.find('CVE_LIST')
            if cve_list:
                # A QID can have multiple CVEs.
                for cve in cve_list:
                    cve = cve.find('ID').text
                    c.execute('INSERT INTO cve_qid VALUES (?, ?)', (cve, qid))
        conn.commit()


def get_list_id(session, list_title):
    """List current search list.

    :param session: requests Session object.
    :param list_title: the title of the search list."""
    resp = _get(session, 'qid/search_list/static', 'list')
    logging.debug(resp)
    root = fromstring(resp.text)
    for sl in root.iter('STATIC_LIST'):
        title = sl.find('TITLE').text
        if title == list_title:
            return sl.find('ID').text


def create_search_list(session, title, qids):
    """Create new search list.

    :param session: requests Session object.
    :param title: A user defined search list title. Maximum is 256 characters (ascii).
    :param qids: QIDs to include in the search list. Ranges are allowed."""
    data = {'title': title,
            'qids': ','.join(qids)}
    resp = _post(session, 'qid/search_list/static', 'create', data)
    logging.debug(resp)
    logging.info('created search list {} with {} QIDs'.format(title, len(qids)))
    return resp.status_code, resp.text


def update_search_list(session, list_id, qids):
    """Update search list.

    :param session: requests Session object.
    :param list_id:  The ID of the search list you want to update.
    :param qids: QIDs to include in the search list. Ranges are allowed."""
    data = {'id': list_id,
            'qids': ','.join(map(str, qids))}
    resp = _post(session, 'qid/search_list/static', 'update', data)
    logging.debug(resp)
    logging.info('updated search list with ID {} with {} QIDs'.format(list_id, len(qids)))
    return resp.status_code, resp.text


def parse_exploited_table(path):
    """Parse exploit list form iSight.

    :param path: Path to CSV file."""
    with open(path, 'r') as f:
        reader = csv.DictReader(f)
        cve_list = set()
        for row in reader:
            cve_raw = row['CVE ID'].strip().upper()
            cve_found = re.search('(CVE-\d{4}-\d{4,})', cve_raw)
            if cve_found:
                cve = cve_found.group(1)
                cve_list.add(cve)
                logging.debug(cve)
    return list(cve_list)


def cve_to_qid(cve_list):
    """Convert CVE to QID.

    :param cve_list: List of CVE IDs."""
    cve_str = "','".join(cve_list)
    with db.connect('qualys.db') as conn:
        c = conn.cursor()
        c.execute("SELECT qid FROM cve_qid WHERE cve IN ('{}')".format(cve_str))
    qid_list = set([row[0] for row in c.fetchall()])
    logging.info('found {} QIDs from {} unique CVEs'.format(len(qid_list), len(cve_list)))
    return list(qid_list)


if __name__ == '__main__':
	import argparse
    import getpass
    import os

    parser = argparse.ArgumentParser()
    parser.add_argument('vulns', help='Path to SV file with iSight vulnerability list')
    parser.add_argument('username', help='Qualys user name')
    parser.add_argument('-p', '--password', help='Qualys password (ommit to get a prompt)')
    args = parser.parse_args()
    password = args.password if args.password else getpass.getpass('Password: ')

    sl_title = 'iSIGHTPartnersExploitedVulnerabilities'

    with connect(args.username, password) as s:
        # Update CVE to QID table.
        update_db(s)
        # Get CVEs from iSight spreadsheet...
        cve_ids = parse_exploited_table(args.vulns)
        # and translate them to QIDs.
        qid_ids = cve_to_qid(cve_ids)
        # Get or create the Qualys search list with the relevant QIDs.
        sl_id = get_list_id(s, sl_title)
        if sl_id:
            r = update_search_list(s, sl_id, qid_ids)
        else:
            r = create_search_list(s, sl_title, qid_ids)
