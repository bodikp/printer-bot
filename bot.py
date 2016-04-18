from __future__ import print_function
import httplib2
import os

from Adafruit_Thermal import *

import base64
import email
from apiclient import errors

from apiclient import discovery
import oauth2client
from oauth2client import client
from oauth2client import tools

from dateutil.parser import parse

import Image, io

try:
    import argparse
    flags = argparse.ArgumentParser(parents=[tools.argparser]).parse_args()
except ImportError:
    flags = None

printer = Adafruit_Thermal("/dev/ttyAMA0", 9600, timeout=5)

# If modifying these scopes, delete your previously saved credentials
# at ~/.credentials/gmail-python-quickstart.json
#SCOPES = 'https://www.googleapis.com/auth/gmail.readonly'
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly','https://www.googleapis.com/auth/gmail.modify']
CLIENT_SECRET_FILE = 'client_secret.json'
APPLICATION_NAME = 'botclient'

service = 0
PRINTED_LABELID = 'Label_1'

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
                                   'gmail-python-printerbot.json')

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

def printExistingLabels():
	results = service.users().labels().list(userId='me').execute()
	labels = results.get('labels', [])

	if not labels:
		print('No labels found.')
	else:
		print('Labels:')
		for label in labels:
			print(label['name']+ " "+label['id'])
	
def getUnreadMessages(service):
	messages = service.users().messages().list(userId='me', labelIds=['UNREAD']).execute()
	return messages.get('messages',[])
	
def getFullMessageFromId(service, id):
	m = service.users().messages().get(userId='me', id=id).execute()
	return m
	
def markMessageAsReadAndPrinted(service, mId):
	body = {'removeLabelIds': ['UNREAD'], 'addLabelIds': [PRINTED_LABELID]}
	service.users().messages().modify(userId='me', id=mId, body=body).execute()
	return
	
def parseMessage(m):
	em = {}
	for kv in m['payload']['headers']:
		if kv['name']=='Date':
			em['date'] = kv['value']
		if kv['name']=='Subject':
			em['subject'] = kv['value']
		if kv['name']=='From':
			em['from'] = kv['value']
		if kv['name']=='To':
			em['to'] = kv['value']
			
	em['labelIds'] = ",".join(m['labelIds'])

	if em.has_key('from'):
		em['from_pretty'] = em['from'].split('<')[0].strip()
	else:
		em['from_pretty'] = ''
		
	if em.has_key('date'):
		em['date_pretty'] = parse(em['date']).strftime('%A, %B %d %Y, %I:%M %p')
	else:
		em['date_pretty'] = ''
	
	#print(m['payload'])
	if ('mimeType' in m['payload']) and (m['payload']['mimeType']=='text/plain'):
		e = m['payload']['body']['data']
	else:
		for part in m['payload']['parts']:
			if part['mimeType'] == 'text/plain':
				e = part['body']['data']
			if part['filename']:
				if 'data' in part['body']:
					print("got filename: "+part['filename'])
					raw_data = part['body']['data']
				else:
					attachmentId = part['body']['attachmentId']
					#print("got attachment: "+part['body']['attachmentId'])
					a = service.users().messages().attachments().get(id=attachmentId,userId='me', messageId=m['id']).execute()		
					raw_data = a['data']
					#print(a)
				file_data = base64.urlsafe_b64decode(raw_data.encode('UTF-8'))
				f = open("attachments/"+part['filename'], 'w')
				f.write(file_data)
				f.close()
				em['attachments'] = {}
				em['attachments'][part['filename']] = file_data

	d = base64.urlsafe_b64decode(e.encode('ASCII'))
	em['body'] = email.message_from_string(d).as_string().strip()

	#for key in email:
	#	print(key + ' = ' + email[key]);

	return em
		
def printEmailToScreen(email):
	print('From: '+email['from_pretty'])
	print('On: '+email['date_pretty'])
	print('Subject: '+email['subject'])
	print(email['body'])
	if 'attachments' in email:
		for a in email['attachments']:
			data = email['attachments'][a];
			i = Image.open(io.BytesIO(data))

def printEmail(email):
	print("printing email")
	printer.print("From: ");
	printer.boldOn();
	printer.println(email['from_pretty'])
	printer.boldOff();

	printer.println(email['date_pretty']);

	printer.print("Subject: ")
	printer.boldOn();
	printer.println(email['subject']);
	printer.boldOff();

	printer.print(email['body']);

	print("printing attachments")
	if 'attachments' in email:
		for a in email['attachments']:
			data = email['attachments'][a];
			i = Image.open(io.BytesIO(data))
			printer.printImage(i, True)

	print("done with email")
	printer.feed(4)

def main():
	global service
	service = getService()

	#printExistingLabels()
	ms = getUnreadMessages(service)

	for m in ms:
		f = getFullMessageFromId(service,m['id'])
		email = parseMessage(f)
		printEmail(email)
		print()
		#markMessageAsReadAndPrinted(service, m['id'])

if __name__ == '__main__':
    main()
