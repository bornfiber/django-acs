import logging
import ssl
import xml.etree.ElementTree as ET
import time
from acs.models import AcsDevice


from django.conf import settings
from sleekxmpp import ClientXMPP
from sleekxmpp.exceptions import IqError, IqTimeout

#logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("django_acs.%s" % __name__)


def do_work():
    """
    The acs_connreq_worker looks for acs_devices needing a connection request, and sends xmpp conn. request.
    """

    ### create AcsXmppBot instance
    xmpp = AcsXmpp(settings.ACS_XMPP_JABBERID, settings.ACS_XMPP_PASSWORD)
    xmpp.ssl_version = ssl.PROTOCOL_TLSv1_2
    xmpp.connect(address=settings.ACS_XMPP_SERVERTUPLE)
    xmpp.process(block=False, timeout=1)
    while True:
        acs_device_list = AcsDevice.objects.filter(connection_request=True)
        for acs_device in acs_device_list:
            AcsDevice.objects.filter(pk=acs_device.pk).update(
                connection_request=False
            )
            print(f"CR: {acs_device}")
            cr = xmpp.connreq_iq(
                f"{acs_device.acs_connectionrequest_username}@{settings.ACS_XMPP_SERVERTUPLE[0]}/acstalk",
                acs_device.acs_connectionrequest_username,
                acs_device.acs_connectionrequest_password,
            )
            try:
                cr.send(timeout=3)
            except IqError as e:
                logger.error(f"IQ Error {e}")
            except IqTimeout as e:
                logger.error(f"IQ Error {e}")

        print("acs_connreq_worker tick.")
        time.sleep(10)


class AcsXmpp(ClientXMPP):
    def __init__(self, jid, password):
        ClientXMPP.__init__(self, jid, password)
        self.add_event_handler("session_start", self.session_start)
        self.add_event_handler("message", self.message)

    def session_start(self, event):
        self.send_presence()
        self.get_roster()

    def message(self, msg):
        if msg["type"] in ("iq", "chat", "normal") or True:
            logger.info(f"received: {msg}")

    def connreq_iq(self, to_jid, username, password):
        iq = self.Iq()
        iq.set_from(settings.ACS_XMPP_JABBERID)
        iq.set_to(to_jid)
        iq.set_type("get")
        iq.appendxml(make_connreq_xml(username, password))

        return iq


def make_connreq_xml(username, password):
    connection_request = ET.Element(
        "connectionRequest", {"xmlns": "urn:broadband-forum-org:cwmp:xmppConnReq-1-0"}
    )
    e_username = ET.SubElement(connection_request, "username")
    e_username.text = username
    e_password = ET.SubElement(connection_request, "password")
    e_password.text = password
    return connection_request
