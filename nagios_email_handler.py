#!/usr/bin/env python

"""Parse commands received by email for nagios.

This script is designed to connect to IMAP mail boxes and download unread
messages. The messages are then parsed to commands to run against nagios."""


import email
import imaplib
import logging
import logging.handlers
import os
import re
import sys
import time


__author__ = "Avleen Vig"
__license__ = "GPL"
__version__ = "1.0"
__maintainer__ = "Avleen Vig"
__email__ = "avleen@gmail.com"
__status__ = "Production"


# Global connection handler. We'll use one connection handler for everything we
# need to do. No need to open hundreds of connections!
CONN = None

# Global logging handler.
LOGGER = None

# CMD file for Nagios
CMD_FILE = '/usr/nagios/var/rw/nagios.cmd'

# IMAP server, username and password
IMAP_SERVER = 'imap.example.com'
IMAP_USER = 'username@example.com'
IMAP_PASS = 'your_password'


def do_sanity_checks():
    """Do some sanity checks before anything else to make sure we're not going
    to break."""
    if not os.path.exists(CMD_FILE):
        print 'Command file %s does not exist!' % CMD_FILE
        sys.exit(1)


def make_logger():
    """Set up the logging module"""
    global LOGGER
    LOGGER = logging.getLogger('nagios_email_handler')
    formatter = logging.Formatter(
                    '%(filename)s[%(process)d]: %(levelname)s: %(message)s')
    syslog_hdlr = logging.handlers.SysLogHandler(
                      facility=logging.handlers.SysLogHandler.LOG_USER)
    syslog_hdlr.setFormatter(formatter)
    syslog_hdlr.setLevel(logging.DEBUG)
    console_hdlr = logging.StreamHandler()
    console_hdlr.setLevel(logging.DEBUG)
    console_hdlr.setFormatter(formatter)
    LOGGER.addHandler(syslog_hdlr)


def imap_login():
    """Connect to the IMAP server"""
    global CONN
    server = IMAP_SERVER
    port = 993
    username = IMAP_USER
    password = IMAP_PASS
    CONN = imaplib.IMAP4_SSL(server, port)
    CONN.login(username, password)
    CONN.select()


def get_messages():
    """Get the newest messages from the IMAP server"""
    typ, data = CONN.search(None, 'UNSEEN')
    for num in data[0].split():
        typ, data = CONN.fetch(num, '(RFC822)')
        yield (num, data[0][1])


def get_email_data(msg):
    """Parse the email message data and extract the data to act on"""
    alert_class = None
    command = None
    fromaddr = None
    server = None
    service = None

    # Make sure the subject matches one we care about
    msg = email.message_from_string(msg)
    subject_p = re.compile('(Host|Service) Alert: (.*?) is', re.IGNORECASE)
    if '<' in msg['From']:
        from_p = re.compile('<([\w\d._%+-]+@[\w\d.-]+\.[\w]{2,4})',
                               re.IGNORECASE)
    else:
        from_p = re.compile('([\w\d._%+-]+@[\w\d.-]+\.[\w]{2,4})',
                               re.IGNORECASE)
    if subject_p.search(msg['Subject']):
        alert_class = subject_p.search(msg['Subject']).group(1)
        server_service = subject_p.search(msg['Subject']).group(2)
        if alert_class.lower() == 'service':
            service = server_service.split('/')[1]
            server = server_service.split('/')[0]
        else:
            server = server_service
        fromaddr = from_p.search(msg['From']).group(1)

        # The command is the first word in the body
        for part in msg.walk():
            if part.get_content_maintype() == 'text' and \
                part.get_content_subtype() == 'plain':
                # Now we have the 'text/plain' part of the message. Find the
                # first word in it, that is our command.
                command = part.get_payload().split()[0].lower()
                break
    return alert_class, fromaddr, server, service, command


def delete_message(msg_uid):
    """Delete messages on the IMAP server"""
    LOGGER.info('Deleted message id: %s' % msg_uid)
    CONN.store(msg_uid, '+FLAGS', '\\Deleted')


def mark_message_read(msg_uid):
    """Mark messages on the IMAP server as read"""
    LOGGER.info('Marked message id read: %s' % msg_uid)
    CONN.store(msg_uid, '+FLAGS', '\\Seen')


def ack_alert(alert_class, fromaddr, server, service):
    """Acknowledge alerts"""
    now = int(time.time())

    if alert_class == 'Host':
        msg = '[%s] ACKNOWLEDGE_HOST_PROBLEM;%s;1;1;1;%s;ACK' % \
               (now, server, fromaddr)
    elif alert_class == 'Service':
        msg = '[%s] ACKNOWLEDGE_SVC_PROBLEM;%s;%s;1;1;1;%s;ACK' % \
               (now, server, service, fromaddr)
    open(CMD_FILE, 'w').write(msg)
    LOGGER.info('ACKed alert: From: %s, Host: %s, Service: %s' % \
                (fromaddr, server, service))


def main():
    do_sanity_checks()

    # Log into the IMAP server
    imap_login()

    # Make the logger
    make_logger()

    for msg_uid, msg in get_messages():
        alert_class, fromaddr, server, service, command = get_email_data(msg)
        LOGGER.info('%s, %s, %s, %s, %s' % (
                    alert_class, fromaddr, server, service, command))
        # Mark the message as read so we don't get it again, if it was to do
        # with an alert. Otherwise delete a message if it doesn't contain
        # something to do with an alert.
        if alert_class:
            print('%s, %s, %s, %s, %s' % (
                  alert_class, fromaddr, server, service, command))
            mark_message_read(msg_uid)
        else:
            delete_message(msg_uid)
            continue

        # Figure out what the admin was trying to do.
        if command.lower().startswith('ack'):
            ack_alert(alert_class, fromaddr, server, service)


if __name__ == '__main__':
    main()
