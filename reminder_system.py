import os
from datetime import datetime
from time import sleep

from apscheduler.schedulers.background import BackgroundScheduler
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

SCOPES = ["https://mail.google.com/"]
our_email = "EventHorizonCalendar@gmail.com"

class ReminderSystem:
    def __init__(self):
        self.test_var = "Test"
        self.scheduler = BackgroundScheduler()
        if not self.gmail_authenticate():
            return
        # should look through database for existing events that have reminders
        # add them to the scheduler
        self.scheduler.start()

    def gmail_authenticate(self):
        creds = None
        # The file token.json stores the user's access and refresh tokens, and is
        # created automatically when the authorization flow completes for the first
        # time.
        if os.path.exists("token.json"):
            creds = Credentials.from_authorized_user_file("token.json", SCOPES)
        # If there are no (valid) credentials available, let the user log in.
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    "credentials.json", SCOPES
                )
                creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open("token.json", "w") as token:
            token.write(creds.to_json())

        try:
            # Call the Gmail API
            service = build("gmail", "v1", credentials=creds)
            results = service.users().labels().list(userId="me").execute()
            labels = results.get("labels", [])

            if not labels:
                print("No labels found.")
                return
            print("Labels:")
            for label in labels:
                print(label["name"])

            return service

        except HttpError as error:
            print(f"An error occurred: {error}")
            return False

    # def send_reminder(self):

    def add_reminder(self, event_id, msg):
        self.scheduler.add_job(self.display, "interval", seconds=3, args=[msg], id=event_id)

    # whenever the user deletes the reminder time or deletes the event
    # def delete_reminder(self, event_id):
    #     self.scheduler.remove_job(event_id)

    def display(self, msg):
        print(msg)

    # edit reminder function
    # whenever the user edits the reminder time on an event