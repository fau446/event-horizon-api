import os
from base64 import urlsafe_b64encode
from datetime import datetime
from email.mime.text import MIMEText
from time import sleep

import pytz
from apscheduler.schedulers.background import BackgroundScheduler
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from pytz import utc

SCOPES = ["https://mail.google.com/"]
our_email = "EventHorizonCalendar@gmail.com"

class ReminderSystem:
    def __init__(self):
        self.test_var = "Test"
        self.scheduler = BackgroundScheduler(timezone=utc)
        self.service = self.__gmail_authenticate()
        if not self.service:
            return
        # should look through database for existing events that have reminders
        # add them to the scheduler
        self.scheduler.start()

    def add_reminder(self, event_id, user_email, event_title, time, user_time_zone):
        reminder_time = self.__convert_to_utc(time, user_time_zone)

        self.scheduler.add_job(self.__send_reminder, "date", run_date = reminder_time, id=event_id, args=[user_email, event_title])

    def __convert_to_utc(self, time, user_time_zone):
        local_time = datetime.strptime(time, "%Y-%m-%dT%H:%M")

        tz = pytz.timezone(user_time_zone)
        local_time_with_tz = tz.localize(local_time)
        
        utc_time = local_time_with_tz.astimezone(pytz.utc)
        
        return utc_time

    def __gmail_authenticate(self):
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

    def __send_reminder(self, user_email, event_title):
        self.__send_message(self.service, user_email, f"[Event Horizon]: Reminder for {event_title}", "This is the message")

    def __build_message(self, destination, obj, body):
        message = MIMEText(body)
        message["to"] = destination
        message["from"] = our_email
        message["subject"] = obj
        return {"raw": urlsafe_b64encode(message.as_bytes()).decode()}
    
    def __send_message(self, service, destination, obj, body):
        return (
            service.users()
            .messages()
            .send(userId="me", body=self.__build_message(destination, obj, body))
            .execute()
        )

    # whenever the user deletes the reminder time or deletes the event
    # def delete_reminder(self, event_id):
    #     self.scheduler.remove_job(event_id)

    # used for testing, remove after
    def display(self, msg):
        print(msg)

    # edit reminder function
    # whenever the user edits the reminder time on an event