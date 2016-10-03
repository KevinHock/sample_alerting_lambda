import boto3
import gzip
import json
import logging
import os
import re
import urllib
import urllib2
import uuid

FILTER_CONFIG  = ''
# Kevin's Personal Account
FILTER_CONFIG_BUCKET = 'kevinsbigbucketofallthelogs'

FILTER_CONFIG_FILE   = 'filter_config.json'
PAGERDUTY_KEY = 'NO_KEYS_IN_SOURCE'
PAGERDUTY_WEBHOOK_URL = 'https://events.pagerduty.com/generic/2010-04-15/create_event.json'
TEMP = '/tmp/'

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.info('Loading function')

# "Handler" is lambda_function.lambda_handler
# Event type: ObjectCreated
def lambda_handler(event, context):
    global FILTER_CONFIG
    s3_client = boto3.client('s3')
    UNLINK_THIS_GZ_AFTER = ''
    UNLINK_THIS_JSON_AFTER = ''

    # Initialize the FILTER_CONFIG
    if FILTER_CONFIG == '':
        # Download filter_config.json from FILTER_CONFIG_BUCKET
        response = s3_client.get_object(Bucket=FILTER_CONFIG_BUCKET, Key=FILTER_CONFIG_FILE)
        body = response['Body'].read()
        FILTER_CONFIG = json.loads(body)

    for record in event['Records']:
        event_bucket = record['s3']['bucket']['name']
        event_key = record['s3']['object']['key']

        # We don't have to worry about "CloudTrail-Digest" files because of Prefix: AWSLogs/ACCOUNT#/CloudTrail

        index = event_key.rfind('/')
        if index == -1:
            logger.info("RFIND DIDNT WORK")
            # Send alert via SNS email?

        file_name = event_key[index+1:]
        logger.info("file_name is "+file_name)

        # Download the gz locally
        download_path = '{}{}_{}'.format(TEMP, uuid.uuid4(), file_name.replace("/","_"))
        UNLINK_THIS_GZ_AFTER = download_path
        logger.info("The download_path is "+download_path)
        s3_client.download_file(event_bucket, event_key, download_path)

        with gzip.open(download_path, "rb") as unzipped:
            all_events = json.loads(unzipped.read())
            for cloudtrail_record in all_events['Records']:
                cloudtrail_event_arn = cloudtrail_record['userIdentity']['arn']
                cloudtrail_event_name = cloudtrail_record['eventName']
                cloudtrail_parameters = str(json.dumps(cloudtrail_record['requestParameters']))

                # If the event is in our alert list
                if re.match(FILTER_CONFIG['regexp'], cloudtrail_event_name):
                    logger.info("Sending an alert to PagerDuty")

                    last_slash = cloudtrail_event_arn.rfind('/')
                    last_colon = cloudtrail_event_arn.rfind(':')
                    user = cloudtrail_event_arn[max(last_slash, last_colon)+1:]

                    if user.startswith("i-"):
                        logger.info("ITS A MACHINE, CHANGING user NOW")
                        user = cloudtrail_event_arn[last_colon+1:]
                    logger.info("The user is "+user)

                    message = "Event: " + cloudtrail_event_name + "\n" + \
                            "User: " + str(cloudtrail_record['userIdentity']) + "\n" + \
                            "Params: " + cloudtrail_parameters + "\n"
                    body = {
                      'service_key': PAGERDUTY_KEY,
                      'event_type': "trigger",
                      'description': "[TEST] "+ str(cloudtrail_event_name) + " @"+ str(user),
                      'details':  json.dumps(message)
                    }
                    encoded_body = json.dumps(body)

                    # requests module is not included in AWS means urllib2 is simpler
                    req = urllib2.Request(PAGERDUTY_WEBHOOK_URL, encoded_body)
                    response = urllib2.urlopen(req)
                    result = response.read()
                    logger.info("Result from PagerDuty is "+str(result))

        # Delete the files leftover in /tmp/
        logger.info('Before here are the files '+str(os.listdir(TEMP)))
        try:
            os.remove(UNLINK_THIS_GZ_AFTER)
        except OSError:
            pass
        logger.info('After here are the files '+str(os.listdir(TEMP)))

        # We are done! :D
        logger.info('Finished handling '+event_bucket+'/'+event_key)
