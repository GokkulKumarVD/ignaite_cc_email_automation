import base64
import requests
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from email import message_from_bytes
from email.utils import parseaddr
import os
import json
import re


# Define the scopes and initialize the Gmail and Drive APIs
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.compose',
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/drive.readonly'
]

# File paths for credentials and token
CREDENTIALS_FILE = 'credentials1.json'
TOKEN_FILE = 'token.json'

def authenticate_google_api():
    """Authenticate and return Google API credentials."""
    creds = None

    # Check if token.json exists (this stores the user's access and refresh tokens)
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'r') as token:
            creds = Credentials.from_authorized_user_info(json.load(token), SCOPES)

    # If there are no valid credentials, prompt the user to log in
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)

        # Save the credentials for the next run
        with open(TOKEN_FILE, 'w') as token:
            token.write(creds.to_json())

    return creds

def authenticate_apis():
    # Authenticate using the provided function
    creds = authenticate_google_api()

    # Initialize both Gmail and Drive services
    gmail_service = build('gmail', 'v1', credentials=creds)
    drive_service = build('drive', 'v3', credentials=creds)

    return gmail_service, drive_service

def get_label_id_by_name(service, label_name):
    try:
        # Retrieve all labels
        results = service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])

        # Find the label ID by name
        for label in labels:
            if label['name'] == label_name:
                return label['id']
        print(f"Label '{label_name}' not found.")
        return None
    except HttpError as error:
        print(f'An error occurred: {error}')
        return None

def search_unread_emails(service, label_id):
    try:
        results = service.users().messages().list(userId='me', labelIds=[label_id], q='is:unread').execute()
        messages = results.get('messages', [])
        return messages
    except HttpError as error:
        print(f'An error occurred: {error}')
        return []

def get_email_content(service, message_id):
    try:
        message = service.users().messages().get(userId='me', id=message_id, format='raw').execute()
        msg_str = base64.urlsafe_b64decode(message['raw'].encode('ASCII'))
        mime_msg = message_from_bytes(msg_str)

        # Extract the sender's email address
        sender_email = parseaddr(mime_msg['From'])[1]

        # Extract the subject
        subject = mime_msg['Subject']

        # Check if the message is multipart
        if mime_msg.is_multipart():
            for part in mime_msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))

                # Look for the plain text or HTML part
                if content_type == "text/plain" and "attachment" not in content_disposition:
                    return part.get_payload(decode=True).decode('utf-8'), sender_email, subject
                elif content_type == "text/html" and "attachment" not in content_disposition:
                    return part.get_payload(decode=True).decode('utf-8'), sender_email, subject
        else:
            # If the message is not multipart, return the payload
            return mime_msg.get_payload(decode=True).decode('utf-8'), sender_email, subject

    except HttpError as error:
        print(f'An error occurred: {error}')
        return None, None, None
    except Exception as e:
        print(f'An unexpected error occurred: {e}')
        return None, None, None

def search_similar_emails(service, issues):
    # Search past emails for similar issues
    similar_emails = []
    for issue in issues:
        results = service.users().messages().list(userId='me', q=issue).execute()
        similar_emails.extend(results.get('messages', []))
    return similar_emails


def clean_response_text(response_text):
    """
    Remove Markdown-style links from the response text.
    Example: Will remove [[1]](https://docs.google.com/document/d...)
    """
    # This pattern matches Markdown-style links with numbers: [[1]](url)
    pattern = r'\[\[[0-9]+\]\]\([^)]+\)'
    cleaned_text = re.sub(pattern, '', response_text)
    return cleaned_text



def fetch_google_drive_details(drive_service, issues):
    # Use the Google Drive API to fetch relevant documents based on identified issues
    relevant_docs = []
    for issue in issues:
        results = drive_service.files().list(q=f"name contains '{issue}'").execute()
        relevant_docs.extend(results.get('files', []))
    return relevant_docs


def draft_response(email_content, similar_emails, relevant_docs):
    # Use the Dashworks LLM API to draft a response
    message = f"Email content: {email_content}\nSimilar emails: {similar_emails}\nRelevant documents: {relevant_docs}"
    response = requests.post(
        "https://api.dashworks.ai/v1/answer",
        headers={
            "Authorization": "Bearer mMHmuvfKtIXnEk-xtyGO50Qs3-D3v5K1DK8ZuYIV5KM",
            "Content-Type": "application/json"
        },
        json={"message": message, "bot_id": "55c5de2bbbec4547a9ea07abf12edf26", "inline_sources": True,
              "stream": False}, verify=False
    )

    # Log the response for debugging
    try:
        data = response.json()
        print(f"Dashworks API Response: {data}")
        response_text = data.get('answer', 'No response generated')

        # Clean the response text to remove any links
        cleaned_response = clean_response_text(response_text)

        return cleaned_response
    except ValueError:
        print("Failed to parse JSON response from Dashworks API.")
        return 'No response generated'
def create_draft(service, user_id, message_body, recipient_email, subject):
    try:
        message = {
            'raw': base64.urlsafe_b64encode(
                f"To: {recipient_email}\r\nSubject: {subject}\r\n\r\n{message_body}".encode('utf-8')
            ).decode('utf-8')
        }
        draft = service.users().drafts().create(userId=user_id, body={'message': message}).execute()
        print(f"Draft id: {draft['id']}\nDraft message: {draft['message']}")
        return draft
    except HttpError as error:
        print(f'An error occurred: {error}')
        return None

def send_email(service, user_id, message_body, recipient_email, subject):
    try:
        message = {
            'raw': base64.urlsafe_b64encode(
                f"To: {recipient_email}\r\nSubject: {subject}\r\n\r\n{message_body}".encode('utf-8')
            ).decode('utf-8')
        }
        sent_message = service.users().messages().send(userId=user_id, body=message).execute()
        print(f"Message Id: {sent_message['id']}")
        return sent_message
    except HttpError as error:
        print(f'An error occurred: {error}')
        return None


def main():
    # Authentication code remains the same...
    gmail_service, drive_service = authenticate_apis()
    label_name = 'Dashwork_testing'
    label_id = get_label_id_by_name(gmail_service, label_name)

    if label_id:
        messages = search_unread_emails(gmail_service, label_id)

        if messages:
            for message in messages:
                email_content, sender_email, subject = get_email_content(gmail_service, message['id'])
                if email_content and sender_email and subject:
                    issues = []  # Placeholder for issues identified from email content
                    similar_emails = search_similar_emails(gmail_service, issues)
                    relevant_docs = fetch_google_drive_details(drive_service, issues)

                    # Get cleaned response with links removed
                    response = draft_response(email_content, similar_emails, relevant_docs)

                    if response != 'No response generated':
                        draft = create_draft(gmail_service, 'me', response, sender_email, subject)
                        if draft:
                            send_email(gmail_service, 'me', response, sender_email, subject)
        else:
            print("No unread emails found with the specified label.")
    else:
        print("Label not found.")

if __name__ == '__main__':
    main()