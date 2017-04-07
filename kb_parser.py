import argparse
import sqlite3 as db
from xml.etree.ElementTree import parse

parser = argparse.ArgumentParser()
parser.add_argument('file', help='Qualys knowledge base XML file')
args = parser.parse_args()


with db.connect('qualys.db') as conn:
    conn.execute('DROP TABLE cve_qid')
    conn.execute('CREATE TABLE cve_qid (cve TEXT, qid INTEGER)')
    tree = parse(args.file)
    root = tree.getroot()
    for vuln in root.iter('VULN'):
        # Every vulnerability has a QID.
        qid = vuln.find('QID').text
        cve_list = vuln.find('CVE_LIST')
        if cve_list:
            # A QID can have multiple CVEs.
            for cve in cve_list:
                cve = cve.find('ID').text
                conn.execute('INSERT INTO cve_qid VALUES (?, ?)', (cve, qid))
    conn.commit()
