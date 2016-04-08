from __future__ import print_function
import httplib2
import os

import base64
import email
from apiclient import errors

from apiclient import discovery
import oauth2client
from oauth2client import client
from oauth2client import tools

try:
    import argparse
    flags = argparse.ArgumentParser(parents=[tools.argparser]).parse_args()
except ImportError:
    flags = None

# If modifying these scopes, delete your previously saved credentials
# at ~/.credentials/gmail-python-quickstart.json
SCOPES = 'https://www.googleapis.com/auth/gmail.readonly'
CLIENT_SECRET_FILE = 'client_secret.json'
APPLICATION_NAME = 'botclient'


def get_credentials():
    """Gets valid user credentials from storage.

    If nothing has been stored, or if the stored credentials are invalid,
    the OAuth2 flow is completed to obtain the new credentials.

    Returns:
        Credentials, the obtained credential.
    """
    home_dir = os.path.expanduser('~')
    credential_dir = os.path.join(home_dir, '.credentials')
    if not os.path.exists(credential_dir):
        os.makedirs(credential_dir)
    credential_path = os.path.join(credential_dir,
                                   'gmail-python-quickstart.json')

    store = oauth2client.file.Storage(credential_path)
    credentials = store.get()
    if not credentials or credentials.invalid:
        flow = client.flow_from_clientsecrets(CLIENT_SECRET_FILE, SCOPES)
        flow.user_agent = APPLICATION_NAME
        if flags:
            credentials = tools.run_flow(flow, store, flags)
        else: # Needed only for compatibility with Python 2.6
            credentials = tools.run(flow, store)
        print('Storing credentials to ' + credential_path)
    return credentials

def getService():
	credentials = get_credentials()
	http = credentials.authorize(httplib2.Http())
	service = discovery.build('gmail', 'v1', http=http)
	return service

def getUnreadMessages(service):
	messages = service.users().messages().list(userId='me', labelIds=['UNREAD']).execute()
	return messages.get('messages',[])
	
def getFullMessageFromId(service, id):
	m = service.users().messages().get(userId='me', id=id).execute()
	return m
	
def markMessageAsRead(mId):
	return
	
def printMessage(m):
	headers = {}
	for kv in m['payload']['headers']:
		if kv['name']=='Date':
			headers['date'] = kv['value']
		if kv['name']=='Subject':
			headers['subject'] = kv['value']
		if kv['name']=='From':
			headers['from'] = kv['value']
		if kv['name']=='To':
			headers['to'] = kv['value']
			
	headers['labelIds'] = ",".join(m['labelIds'])

	for part in m['payload']['parts']:
		if part['mimeType'] == 'text/plain':
			e = part['body']['data']
			d = base64.urlsafe_b64decode(e.encode('ASCII'))
			headers['body'] = email.message_from_string(d).as_string()

	for key in headers:
		print(key + ' = ' + headers[key]);
	#print('body: '+body)
	
def main():
	service = getService()
	ms = getUnreadMessages(service)

	for m in ms:
		f = getFullMessageFromId(service,m['id'])
		printMessage(f)

    # results = service.users().labels().list(userId='me').execute()
    # labels = results.get('labels', [])

    # if not labels:
        # print('No labels found.')
    # else:
      # print('Labels:')
      # for label in labels:
        # print(label['name'])


if __name__ == '__main__':
    main()