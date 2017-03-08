import boto3
import datetime
import gzip
import json
import logging
import os
import re
import urllib
import urllib2
import uuid

from botocore.client import Config
from dateutil.relativedelta import relativedelta

CLOUDSEARCH_ENDPOINT = 'https://search-FILL_IT_IN.cloudsearch.amazonaws.com'
FILTER_CONFIG = {
   "regexp" : [
                "AuthorizeSecurityGroupIngress",
                "FILL_IT_IN"
            ]
}
# Joining it like this just makes it easier to diff
FILTER_CONFIG['regexp'] = '|'.join(FILTER_CONFIG['regexp'])

PAGERDUTY_KEY = 'NO_KEYS_IN_SOURCE'
PAGERDUTY_WEBHOOK_URL = 'https://events.pagerduty.com/generic/2010-04-15/create_event.json'
TEMP = '/tmp/'

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# "Handler" is lambda_function.lambda_handler
def lambda_handler(event, context):
    global FILTER_CONFIG
    s3_client = boto3.client('s3', config=Config(signature_version='s3v4'))
    cs_client = boto3.client('cloudsearchdomain', endpoint_url=CLOUDSEARCH_ENDPOINT, region_name='us-east-1')

    UNLINK_THIS_GZ_AFTER = ''
    UNLINK_THIS_JSON_AFTER = ''

    for sns_stuff in event['Records']:
        transformed_message = json.loads(sns_stuff['Sns']['Message'])
        for record in transformed_message['Records']:
            event_bucket = record['s3']['bucket']['name']
            event_key = record['s3']['object']['key']

            # Note: We do not process the CloudTrail-Digest files.
            # This is done via setting Prefix to AWSLogs/ACCOUNT_ID/CloudTrail

            index = event_key.rfind('/')
            if index == -1:
                logger.error("RFIND DIDNT WORK")
                # Send PagerDuty alert?

            file_name = event_key[index+1:]
            # Download the gz locally
            download_path = '{}{}_{}'.format(TEMP, uuid.uuid4(), file_name.replace("/","_"))
            UNLINK_THIS_GZ_AFTER = download_path
            try:
                s3_client.download_file(event_bucket, event_key, download_path)
            except Exception:
                logger.error("OH NO WE CAN'T DOWNLOAD FROM THE BUCKET NO MORE")

                message = "Event: " + "STUFF AINT DOWNLOADING ON FILL_IT_IN" + "\n" + \
                        "User: " + "oh no" + "\n" + \
                        "awsRegion:" + "oh no" + "\n" + \
                        "eventID:" + "oh no" + "\n" + \
                        "eventTime:" + "oh no" + "\n" + \
                        "fileName:" + "uh oh" + "\n" + \
                        "Params: " + "sad" + "\n"
                body = {
                  'service_key': PAGERDUTY_KEY,
                  'event_type': "trigger",
                  'description': ""+ "STUFF AINT WORKING ON FILL_IT_IN" + " @FILL_IT_IN",
                  'details':  json.dumps(message)
                }
                encoded_body = json.dumps(body)

                # requests module is not included in AWS means urllib2 is simpler
                req = urllib2.Request(PAGERDUTY_WEBHOOK_URL, encoded_body)
                response = urllib2.urlopen(req)
                result = response.read()
                logger.info("Result from PagerDuty is "+str(result))
                raise
            with gzip.open(download_path, "rb") as unzipped:
                all_events = json.loads(unzipped.read())
                # CloudSearch needs a weird list format
                event_documents = "["
                for cloudtrail_record in all_events['Records']:
                    try:
                        cloudtrail_event_arn = cloudtrail_record['userIdentity']['arn']

                        last_slash = cloudtrail_event_arn.rfind('/')
                        last_colon = cloudtrail_event_arn.rfind(':')
                        user = cloudtrail_event_arn[max(last_slash, last_colon)+1:]

                        # If it is a machine
                        if user.startswith("i-"):
                            user = cloudtrail_event_arn[last_colon+1:]
                            #logger.info("ITS A MACHINE, CHANGING user NOW to %s", user)
                    except Exception:
                        user = cloudtrail_record['userIdentity']

                    cloudtrail_event_name = cloudtrail_record['eventName']
                    cloudtrail_parameters = str(json.dumps(cloudtrail_record['requestParameters']))

                    # Check if S3 messed up and sent us an outdated event
                    now = datetime.datetime.utcnow()
                    thirty_minutes_ago = now + relativedelta(minutes=-30)
                    event_time = datetime.datetime.strptime(cloudtrail_record['eventTime'], "%Y-%m-%dT%H:%M:%SZ")
                    description = str(cloudtrail_event_name) + " @"+ str(user)
                    if event_time < thirty_minutes_ago:
                        description = "Outdated event, resolve me. Tell FILL_IT_IN"

                    # If the event is in our alert list
                    if re.match(FILTER_CONFIG['regexp'], cloudtrail_event_name):
                        logger.info("Sending an alert to PagerDuty")
                        logger.info("The user is "+user)
                        logger.info("The event_name is %s", cloudtrail_event_name)

                        message = "Event: " + cloudtrail_event_name + "\n" + \
                                "User: " + str(cloudtrail_record['userIdentity']) + "\n" + \
                                "awsRegion:" + str(cloudtrail_record['awsRegion']) + "\n" + \
                                "eventID:" + str(cloudtrail_record['eventID']) + "\n" + \
                                "eventTime:" + str(cloudtrail_record['eventTime']) + "\n" + \
                                "fileName:" + file_name + "\n" + \
                                "Params: " + cloudtrail_parameters + "\n"
                        body = {
                          'service_key': PAGERDUTY_KEY,
                          'event_type': "trigger",
                          'description': description,
                          'details':  json.dumps(message)
                        }
                        encoded_body = json.dumps(body)

                        # requests module is not included in AWS means urllib2 is simpler
                        req = urllib2.Request(PAGERDUTY_WEBHOOK_URL, encoded_body)
                        response = urllib2.urlopen(req)
                        result = response.read()
                        logger.info("Result from PagerDuty is "+str(result))

                    # CloudSearch code starts here!
                    NO_CLUE = "No clue, wasn't in record!-FILL_IT_IN"

                    try:
                        user_identity_user_name = cloudtrail_record['userIdentity']['userName']
                    except KeyError:
                        try:
                            user_identity_user_name = cloudtrail_record['userIdentity']['sessionContext']['sessionIssuer']['userName']
                        except KeyError:
                            # logger.error("So the record with no user_identity_user_name is %s", cloudtrail_record)
                            user_identity_user_name = NO_CLUE

                    try:
                        user_identity_arn = cloudtrail_record['userIdentity']['arn']
                    except KeyError:
                        # logger.error("So the record with no user_identity_arn is %s", cloudtrail_record)
                        user_identity_arn = NO_CLUE

                    try:
                        user_identity_account_id = cloudtrail_record['userIdentity']['accountId']
                    except KeyError:
                        # logger.error("So the record with no accountId is %s", cloudtrail_record)
                        user_identity_account_id = NO_CLUE

                    fields = {
                        'aws_region': cloudtrail_record['awsRegion'],
                        'event_id': cloudtrail_record['eventID'],
                        'event_name': cloudtrail_record['eventName'],
                        'event_source': cloudtrail_record['eventSource'],
                        'event_time': cloudtrail_record['eventTime'],
                        'source_ip_address': cloudtrail_record['sourceIPAddress'],
                        'user_agent': cloudtrail_record['userAgent'],
                        'user_identity_type': cloudtrail_record['userIdentity']['type'],
                        'user_identity_arn': user_identity_arn,
                        'user_identity_account_id': user_identity_account_id,
                        'user_identity_user_name': user_identity_user_name,
                        'aws_account': 'FILL_IT_IN'
                    }
                    body = {
                        'type': 'add',
                        'id': cloudtrail_record['eventID'],
                        'fields': fields
                    }
                    event_documents = event_documents + str(json.dumps(body)) + ","
                event_documents = event_documents[:-1] + "]"
                response = cs_client.upload_documents(
                    documents=event_documents,
                    contentType='application/json'
                )

            # Delete the files leftover in /tmp/
            logger.info('Before here are the files '+str(os.listdir(TEMP)))
            try:
                os.remove(UNLINK_THIS_GZ_AFTER)
            except OSError:
                pass
            logger.info('After here are the files '+str(os.listdir(TEMP)))

            # We are done! :D
            logger.info('Finished handling '+event_bucket+'/'+event_key)

