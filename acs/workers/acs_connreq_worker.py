import logging
import ssl
from acs.models import AcsDevice
import xml.etree.ElementTree as ET
from django.conf import settings
from slixmpp import ClientXMPP
from time import sleep
from slixmpp.exceptions import IqError, IqTimeout

# logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("django_acs.%s" % __name__)


def make_connreq_xml(username, password):
    connection_request = ET.Element("connectionRequest", {"xmlns": "urn:broadband-forum-org:cwmp:xmppConnReq-1-0"})
    e_username = ET.SubElement(connection_request, "username")
    e_username.text = username
    e_password = ET.SubElement(connection_request, "password")
    e_password.text = password
    return connection_request


class AcsXmpp(ClientXMPP):
    def __init__(self, jid, password):
        super().__init__(jid, password)
        self.add_event_handler('session_start', self.start)

    async def start(self, event):
        self.send_presence()
        await self.get_roster()

    def connreq_iq(self, to_jid, username, password):
        iq = self.make_iq_get(
            ito="AcsDevice7299@acsxmpp.bornfiber.dk/acstalk",
            ifrom="mrx@acsxmpp.bornfiber.dk/acstalk"
        )
        iq.appendxml(make_connreq_xml(username, password))
        return self.loop.run_until_complete(iq.send(timeout=3))

def do_work():
    xmpp = AcsXmpp(settings.ACS_XMPP_JABBERID, settings.ACS_XMPP_PASSWORD)
    xmpp.ssl_version = ssl.PROTOCOL_TLSv1_2
    xmpp.connect(address=settings.ACS_XMPP_SERVERTUPLE)

    while True:
        acs_device_list = AcsDevice.objects.filter(connection_request=True)[:10]
        for acs_device in acs_device_list:
            AcsDevice.objects.filter(pk=acs_device.pk).update(
                connection_request=False
            )
            print(f"CR: {acs_device}")
            try:
                result = xmpp.connreq_iq(
                    f"{acs_device.acs_connectionrequest_username}@{settings.ACS_XMPP_SERVERTUPLE[0]}/acstalk",
                    acs_device.acs_connectionrequest_username,
                    acs_device.acs_connectionrequest_password,
                )
            except IqError as e:
                logger.error(f"IQ Error {e}")
            except IqTimeout as e:
                logger.error(f"IQ Timeout Error {e}")

        print("acs_connreq_worker tick.")
        sleep(10)
