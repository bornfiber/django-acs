import json, logging, uuid
from lxml import etree
from ipware.ip import get_ip
from defusedxml.lxml import fromstring
from datetime import timedelta

from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views.generic import View
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseServerError
from django.conf import settings
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.db.models import F


from .models import *
from .utils import get_value_from_parameterlist, create_xml_document
from .response import nse, get_soap_envelope,get_soap_xml_object
from .conf import acs_settings

logger = logging.getLogger('django_acs.%s' % __name__)


class AcsServerView2(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        # Like a general in a war, this dispatch method is only here to get decorated
        return super(AcsServerView2, self).dispatch(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        # Get the session, if none found return a new in memory only session
        acs_session = _get_acs_session(request,AcsSession)

        # Get a bool that tells us if the client exceeds the ratelimit
        exceeds_ratelimit = _ratelimit_acs_sessions(acs_session)

        # Reject the request if it exceeds the ratelimit
        if exceeds_ratelimit:
            return HttpResponse(status=420)

        # Empty posts without a session are discarded at once.
        if not request.body and not acs_session.pk:
            logger.info(f"Discarding request without body because it has no session. (ip: {acs_session.client_ip})")
            return HttpResponseBadRequest()

        # If the acs_Session is in memory only, we save it now.
        if not acs_session.pk:
            acs_session.save()

        # Save the acs_http_request, and return the acs_http_request, request_xml and request_headerdict.
        acs_http_request,request_xml,request_headerdict = _save_acs_http_request(acs_session,request)

        # If we have a request body, try to parse it.
        if acs_http_request.body:
            # If we don't have a valid XML body, stop here.
            if request_xml is None:
                message = f"Invalid XML body posted by client (ip: {acs_session.client_ip}"
                logger.warning(message)
                return HttpResponseBadRequest(message)

            # Validate XML namespce
            xml_ns = _get_xml_ns(request_xml,acs_session)
            if xml_ns:
                acs_session.cwmp_namespace = xml_ns
            else:
                return HttpResponseBadRequest("Request XML is malformed.")

            # Validate SOAP request
            soap_body = _validate_soap(request_xml,acs_http_request)

            if soap_body is not None:
                acs_http_request.request_soap_valid = True
            else:
                return HttpResponseBadRequest("Request SOAP is malformed.")

        else:
            # We dit not receive a body,set it to None
            acs_http_request.cwmp_id = ''
            acs_http_request.soap_element = '{%s}(empty request body)' % acs_http_request.acs_session.soap_namespaces['cwmp']

        # Basic validation is now done. Save the acs_session
        acs_http_request.save()
        acs_session.save()

        # Get the hook state
        hook_state = json.loads(acs_session.hook_state)

        hook_list = [
            (_process_inform,"_process_inform"),
            (_preconfig,"_preconfig"),
            (_verify_client_ip,"_verify_client_ip"),
            (_device_firmware_upgrade,"_device_firmware_upgrade"),
        ]

        ### CALL THE HOOKS
        for (hook_function,hook_state_storage) in hook_list:
            response_root,response_body,new_hook_state = hook_function(acs_http_request,hook_state.get(hook_state_storage,{}).copy())
            hook_state[hook_state_storage] = new_hook_state
            acs_session.hook_state = json.dumps(hook_state)
            acs_session.save()
            if response_root == False:
                # Something is wrong, kill the session.
                response = HttpResponseBadRequest()
                response['Set-Cookie'] = f"acs_session_id={acs_session.hexid}; Max-Age=60; Path=/"
                return response
            elif response_root == None:
                # The hook did not want to do anything.
                pass
            else:
                # Sent the response returned from the hook.
                response_data = etree.tostring(response_root, encoding='utf-8', xml_declaration=True)
                response = HttpResponse(response_data, content_type='text/xml; charset=utf-8')
                response['Set-Cookie'] = f"acs_session_id={acs_session.hexid}; Max-Age=60; Path=/"
                # The hook returned a resonse, save it and send it.
                acs_http_response = acs_http_request.rpc_responses.create(
                    http_request = acs_http_request,
                    fk_body=create_xml_document(xml=response.content),
                    cwmp_id=acs_http_request.cwmp_id,
                    soap_element = response_body[0].tag
                )
                return response


        # If we end up here, no hook wanted to do anything. End the session.
        logger.info("End of view !!")

        response = HttpResponse(status=204)
        response['Set-Cookie'] = f"acs_session_id={acs_session.hexid}; Max-Age=60; Path=/"

        # Save the empty response
        acs_http_response = acs_http_request.rpc_responses.create(
            http_request = acs_http_request,
            fk_body=create_xml_document(xml=response.content),
            cwmp_id=acs_http_request.cwmp_id,
            soap_element = f"EmptyResponse",
        )
        # Update the session with result.
        acs_session.session_result = True
        acs_session.save()

        return response


### AcsServerView2 helper functions ###

def _preconfig(acs_http_request,hook_state):

    model_preconfig = '''

    '''


def _device_firmware_upgrade(acs_http_request,hook_state):
    acs_session = acs_http_request.acs_session
    acs_device = acs_session.acs_device

    if 'firmware_ok' in hook_state.keys():
        return None,None,hook_state

    if 'download_ok' in hook_state.keys():
        return None,None,hook_state

    if 'download_failed' in hook_state.keys():
        return None,None,hook_state

    if 'download_cwmp_id' in hook_state.keys():
        # We have issued a download command, lets check if the response matches the cwmp id.
        if acs_http_request.cwmp_rpc_method == "DownloadResponse":
            logger.info(f"{acs_session}: Checking if DownloadResponse is ok.")
            cwmp_payload = acs_http_request.soap_body.find('cwmp:%s' % acs_http_request.cwmp_rpc_method, acs_http_request.acs_session.soap_namespaces).find('Status')
            status_code = cwmp_payload.find("Status")
            if status_code is None:
                logger.info(f"{acs_session}: {acs_device} sent DownloadResponse without status code")
            else:
                if status_code.text in ['0','1']:
                    logger.info(f"{acs_session}: {acs_device} responded with status_code: {status_code.text} in DownloadResponse.")
                    hook_state['download_ok'] = str(timezone.datetime.now())
                else:
                    logger.info(f"{acs_session}: {acs_device} responded with status_code: {status_code.text} in DownloadResponse.")
                    hook_state['download_failed'] = str(timezone.datetime.now())

            return None,None,hook_state

    if acs_device.current_software_version != acs_device.get_desired_software_version():
        # If we need a different software we upgrade the device.
        logger.info(f"{acs_session}: Updating firmware on {acs_device}, {acs_device.current_software_version} -> {acs_device.get_desired_software_version()}")
        response_cwmp_id = uuid.uuid4().hex
        root, body = get_soap_envelope(response_cwmp_id, acs_session)
        software_url = acs_device.get_software_url(version=acs_device.get_desired_software_version())
        cwmp_obj = fromstring(get_soap_xml_object(cwmp_rpc_method="Download",datadict={"url": software_url}))
        cmdkey = etree.SubElement(cwmp_obj, 'CommandKey')
        cmdkey.text = response_cwmp_id
        body.append(cwmp_obj)
        hook_state['download_cwmp_id'] = response_cwmp_id
        response = etree.tostring(root)

        return root,body,hook_state

    # If we end here, the firmware version is OK
    logger.info(f"{acs_session}: Not updating firmware on {acs_device}, as it is the correct version.")
    hook_state['firmware_ok'] = str(timezone.datetime.now())
    return None,None,hook_state


def _verify_client_ip(acs_http_request,hook_state):
    acs_session = acs_http_request.acs_session
    if 'client_ip_verified' in hook_state.keys():
        # If the client IP is already verified do nothing.
        return None,None,hook_state

    # set acs_session.client_ip_verified based on the outcome of verify_acs_client_ip(acs_session.client_ip) 
    acs_session.client_ip_verified = acs_session.acs_device.get_related_device().verify_acs_client_ip(acs_session.client_ip)
    logger.info(f"{acs_session}: client_ip_verified set to {acs_session.client_ip_verified} for client (ip: {acs_session.client_ip})")
    acs_session.save()

    hook_state["client_ip_verified"] = str(timezone.datetime.now())
    return None,None,hook_state


def _process_inform(acs_http_request,hook_state):
    acs_session = acs_http_request.acs_session
    acs_device = acs_session.acs_device

    # Check the hook_state
    if acs_http_request.cwmp_rpc_method == 'Inform' and 'inform_received' in hook_state.keys():
        # If we receive a second Inform in the same session, signal this as an error.
        logger.info(f"{acs_session}: We have received an inform already in this sesson")
        hook_state['inform_multiple_error'] = str(timezone.datetime.now())
        return False,None,hook_state

    elif 'inform_done' in hook_state.keys():
        # The inform is done.
        # Do nothing.
        return None,None,hook_state

    elif 'inform_received' in hook_state.keys() and acs_http_request.soap_body is False:
        # This is the empty post that indicates that the inform phase is done.
        # Do nothing, and mark the inform as done.
        hook_state['inform_done'] = str(timezone.datetime.now())
        return None,None,hook_state

    elif acs_http_request.cwmp_rpc_method == 'TransferComplete':
        logger.info(f"{acs_session}: {acs_device} sent a TransferComplete message.")

        # Inform processed OK, prepare a response
        root, body = get_soap_envelope(acs_http_request.cwmp_id, acs_session)
        cwmp = etree.SubElement(body, nse('cwmp', 'TransferCompleteResponse'))
        ### add the inner response elements, without namespace (according to cwmp spec!)
        maxenv = etree.SubElement(cwmp, 'MaxEnvelopes')
        maxenv.text = '1'
        hook_state['transfer_complete'] = str(timezone.datetime.now())
        return root,body,hook_state

    elif acs_http_request.cwmp_rpc_method != 'Inform':
        # If we receive anything that is not an inform, throw an error.
        logger.info(f"{acs_session}: The session must begin with an inform. Request {acs_http_request} is not an inform.")
        return False,None,hook_state


    # If we make to here, we process the inform.
    # A session has to begin with an inform, so if we get anything else we throw an error.


    ### get Inform xml element
    inform = acs_http_request.soap_body.find('cwmp:Inform', acs_session.soap_namespaces)


    ### determine which data model version this device is using
    datamodel, created = CwmpDataModel.objects.get_or_create(
        name=acs_http_request.acs_session.determine_data_model(inform)
    )
    logger.info(f"{acs_session}: ACS client is using data model %s" % datamodel)
    acs_session.root_data_model = datamodel

    deviceid = inform.find('DeviceId')
    mandatory_inform_fields = ['SerialNumber','Manufacturer','ProductClass','OUI']
    for inform_field in mandatory_inform_fields:
        field_value = deviceid.find(inform_field)
        if field_value is None or field_value == "":
            message = f"{acs_session}: Invalid Inform, {inform_field} missing from request."
            logger.info(message)
            return False,None,hook_state

    #########################################################################
    ### get deviceid element from Inform request


    ### find or create acs devicevendor (using Manufacturer and OUI)
    acs_devicevendor, created = AcsDeviceVendor.objects.get_or_create(
        name__iexact = deviceid.find("Manufacturer").text,
        oui = deviceid.find("OUI").text,
        defaults = {
            "name": deviceid.find("Manufacturer").text,
        }
    )

    ### find or create acs devicetype (using ProductClass)
    acs_devicemodel, created = AcsDeviceModel.objects.get_or_create(
        vendor = acs_devicevendor,
        name__iexact = deviceid.find("ProductClass").text,
        defaults = {
            "name": deviceid.find("ProductClass").text,
        }
    )

    ### find or create acs device (using serial number and acs devicetype)
    acs_device, created = AcsDevice.objects.get_or_create(
        model = acs_devicemodel,
        serial = deviceid.find("SerialNumber").text
    )

    ### set latest session result to False and increase inform count
    acs_device.acs_latest_session_result = False
    acs_device.acs_inform_count = F('acs_inform_count') + 1
    acs_device.save()

    # save acs_device to acs_session
    acs_session.acs_device = acs_device
    acs_session.save()

    # attempt acs device association
    if not acs_device.get_related_device():
        acs_device.associate_with_related_device()

    if not acs_device.acs_xmpp_password:
        acs_device.create_xmpp_user()

    if not acs_device.acs_connectionrequest_password:
        acs_device.create_connreq_password()

    if not acs_session.get_inform_eventcodes(inform, acs_http_request):
        # the event section is missing from this Inform
        return HttpResponseBadRequest(),hook_state

    # Inform processed OK, prepare a response
    root, body = get_soap_envelope(acs_http_request.cwmp_id, acs_session)
    cwmp = etree.SubElement(body, nse('cwmp', 'InformResponse'))
    ### add the inner response elements, without namespace (according to cwmp spec!)
    maxenv = etree.SubElement(cwmp, 'MaxEnvelopes')
    maxenv.text = '1'

    hook_state['inform_received'] = str(timezone.datetime.now())
    return root,body,hook_state


################################################################################################################################

def _validate_soap(request_xml,acs_http_request):
    soap_header = request_xml.find('soap-env:Header', acs_http_request.acs_session.soap_namespaces)
    soap_body = request_xml.find('soap-env:Body', acs_http_request.acs_session.soap_namespaces)

    if soap_body is None:
        # a soap body is required..
        logger.info(f"{acs_http_request.acs_session}: Unable to find SOAP body in xml posted by client (ip: {acs_http_request.acs_session.ip})")
        return False

    if soap_header is not None:
        ### parse the cwmp id from the soap header
        acs_http_request.cwmp_id = soap_header.find('cwmp:ID', acs_http_request.acs_session.soap_namespaces).text
        acs_http_request.soap_element = list(soap_body)[0].tag
        acs_http_request.save()
        ### do we have exactly one soap object in this soap body?
        if len(list(soap_body)) != 1:
            logger.info(f"{acs_http_request.acs_session}: Client sent multiple SOAP bodies (ip: {acs_http_request.acs_session.ip}")
            return False
        else:
            return soap_body


def _get_xml_ns(request_xml,acs_session):
    # Va:lidate that we indeed have a CMWP request that is valid, and extract the SOAP data.    else:
    if not 'cwmp' in request_xml.nsmap:
        logger.info(f"{acs_session}, No cwmp namespace found in the soap envelope, this is not a valid CWMP request posted by client (ip: {acs_session.ip})")
        return False
    else:
        return request_xml.nsmap['cwmp']

def _get_acs_session(request,AcsSession):
    ip = get_ip(request)
    # Do we have an acs_session_id cookie ?
    if 'acs_session_id' in request.COOKIES:
        hexid = request.COOKIES['acs_session_id']

        # See if we have an unfinished ACS session already
        try:
            acs_session = AcsSession.objects.get(acs_session_id=hexid, session_result=False)
            logger.info(f"Got {acs_session} cookie from client (ip: {ip}), and found a valid acs_session.")
            return acs_session
        except AcsSession.DoesNotExist:
            logger.info(f"Invalid acs_session_id from client (ip: {ip}), creating new acs_session")

    else:
        logger.info(f"Got no acs_session cookie from client (ip: {ip}), creating new acs_session")

    # Create a new acs_session, if no valid session found
    return AcsSession(client_ip=ip,hook_state=json.dumps({}))


def _ratelimit_acs_sessions(acs_session):
    inform_interval = acs_settings.INFORM_INTERVAL
    inform_limit = acs_settings.INFORM_LIMIT_PER_INTERVAL
    # If the acs_Session has a pk, it is a pre exsisting session from the DB, allow it.
    if acs_session.pk:
        return False

    # Count the number of previous ACS sessions from thios client ip, within the inform_interval.
    session_count = AcsSession.objects.filter(
        client_ip=acs_session.client_ip,
        created_date__gt=timezone.now()-timedelta(seconds=inform_interval),
    ).count()

    # If we have more than allowed sessions within the informinterval, reject the request.
    if session_count > inform_limit:
        logger.info(f"acs session for client (ip: {acs_session.client_ip}) denied, seen {session_count} sessions, limit is {inform_limit}")
        return True

    # Allow the session
    return False

def _parse_acs_request_header(request,acs_session):
    headerdict = {}
    for key, value in request.META.items():
        ### in django all HTTP headers are prefixed with HTTP_ in request.META
        if key[:5] == 'HTTP_':
            headerdict[key] = value
    return headerdict

def _parse_acs_request_xml(request,acs_session):
    if request.body:
        try:
            xmlroot = fromstring(request.body.decode('utf-8','ignore').encode('utf-8'))
            return xmlroot
        except Exception as E:
            logger.info(f"got exception parsing ACS XML: {E}")
    return None

def _save_acs_http_request(acs_session,request):
    request_headerdict = _parse_acs_request_header(request,acs_session)
    request_xml = _parse_acs_request_xml(request,acs_session)

    validxml = False
    if request_xml is not None:
        validxml = True

    acs_http_request = acs_session.acs_http_requests.create(
        request_headers=json.dumps(request_headerdict),
        request_xml_valid=validxml,
        fk_body=create_xml_document(xml=request.body),
    )

    logger.info(f"{acs_session}: saved {acs_http_request} to db")
    return acs_http_request,request_xml,request_headerdict


### OLD AcsServerView ###

class AcsServerView(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        '''
        Like a general in a war, this dispatch method is only here to get decorated
        '''
        return super(AcsServerView, self).dispatch(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        ### get the client IP from the request
        ip = get_ip(request)
        informinterval = acs_settings.INFORM_INTERVAL

        ### check if we have an acs session id in a cookie
        if 'acs_session_id' in request.COOKIES:
            hexid = request.COOKIES['acs_session_id']
            try:
                acs_session = AcsSession.objects.get(acs_session_id=hexid)
                acs_session.acs_log("got acs_session_id from acs_session_id cookie")
            except AcsSession.DoesNotExist:
                ### create a new AcsSession? only if we haven't already got enough sessions from this client ip
                sessions_since_informinterval = AcsSession.objects.filter(
                    client_ip=ip,
                    created_date__gt=timezone.now()-timedelta(seconds=informinterval),
                ).count()

                if sessions_since_informinterval > acs_settings.INFORM_LIMIT_PER_INTERVAL:
                    message = "acs session DENIED: the IP %s already has %s sessions the last %s seconds, no thanks (limit is %s)" % (ip, sessions_since_informinterval, informinterval, acs_settings.INFORM_LIMIT_PER_INTERVAL)
                    print(message)
                    return HttpResponse(status=420)

                acs_session = AcsSession.objects.create(
                    client_ip=ip,
                )
                hexid = acs_session.hexid
                acs_session.acs_log("got invalid acs_session_id %s from acs_session_id cookie, new acs session created" % request.COOKIES['acs_session_id'])
        else:
            ### no acs_session_id cookie seen, create a new AcsSession? only if we haven't already got enough sessions from this client ip
            sessions_since_informinterval = AcsSession.objects.filter(
                client_ip=ip,
                created_date__gt=timezone.now()-timedelta(seconds=informinterval),
            ).count()

            if sessions_since_informinterval > acs_settings.INFORM_LIMIT_PER_INTERVAL:
                message = "acs session DENIED: the IP %s already has %s sessions the last %s seconds, no thanks (limit is %s)" % (ip, sessions_since_informinterval, informinterval, acs_settings.INFORM_LIMIT_PER_INTERVAL)
                print(message)
                return HttpResponse(status=420)

            acs_session = AcsSession.objects.create(
                client_ip=ip,
            )
            ### and save the acs session ID (uuid.hex()) in the django session for later use
            hexid = acs_session.acs_session_id.hex
            acs_session.acs_log("created new acs session (had %s sessions in the latest informinterval)" % sessions_since_informinterval)

        ### do we have a body in this http request? attempt parsing it as XML if so
        validxml=False
        if request.body:
            try:
                xmlroot = fromstring(request.body)
                validxml=True
            except Exception as E:
                acs_session.acs_log('got exception parsing ACS XML: %s' % E)

        ### get all HTTP headers for this request
        headerdict = {}
        for key, value in request.META.items():
            ### in django all HTTP headers are prefixed with HTTP_ in request.META
            if key[:5] == 'HTTP_':
                headerdict[key] = value

        ### save this HTTP request to DB
        acs_http_request = AcsHttpRequest.objects.create(
            acs_session=acs_session,
            request_headers=json.dumps(headerdict),
            request_xml_valid=validxml,
            fk_body=create_xml_document(xml=request.body),
        )
        acs_session.acs_log("saved acs http request %s to db" % acs_http_request)

        if request.body:
            ### bail out if we have a bad xml body
            if not validxml:
                message = 'Invalid XML body posted by client %s' % ip
                acs_session.acs_log(message)
                return HttpResponseBadRequest(message)

            ### figure out which cwmp version we are speaking (if any)
            if not 'cwmp' in xmlroot.nsmap:
                message = 'No cwmp namespace found in soap envelope, this is not a valid CWMP request posted by client %s' % ip
                acs_session.acs_log(message)
                return HttpResponseBadRequest(message)
            else:
                acs_session.cwmp_namespace = xmlroot.nsmap['cwmp']
                acs_session.save()

            ### parse soap header and body
            soap_header = xmlroot.find('soap-env:Header', acs_session.soap_namespaces)
            soap_body = xmlroot.find('soap-env:Body', acs_session.soap_namespaces)
            if soap_body is None:
                # a soap body is required..
                message = 'Unable to find SOAP body in xml posted by client %s' % ip
                acs_session.acs_log(message)
                return HttpResponseBadRequest(message)

            if soap_header is not None:
                ### parse the cwmp id from the soap header
                acs_http_request.cwmp_id = soap_header.find('cwmp:ID', acs_session.soap_namespaces).text

            ### do we have exactly one soap object in this soap body?
            if len(list(soap_body)) != 1:
                acs_http_request.save()
                message = 'Only one cwmp object per soap envelope please (client: %s)' % ip
                acs_session.acs_log(message)
                return HttpResponseBadRequest(message)
            else:
                ### this appears (for now) to be a valid soap envelope
                acs_http_request.request_soap_valid = True

            ### get the soap element in the format {namespace}Method
            acs_http_request.soap_element = list(soap_body)[0].tag

        else:
            ### empty request body, this means that the CPE is done for now
            acs_http_request.cwmp_id = ''
            acs_http_request.soap_element = '{%s}(empty request body)' % acs_http_request.acs_session.soap_namespaces['cwmp']

        ### save the http request
        acs_http_request.save()

        ################# http request saved to acs session, now we have to put a response together ##################
        ################# at this point we still have not associated the acs session with an acs device, #############
        ################# and we can only do so if we have a valid inform with vendor, serial etc. for the device ####
        if not acs_session.acs_device:
            # we only permit Inform requests when we have no device
            if acs_http_request.cwmp_rpc_method != "Inform":
                message = 'An ACS session must begin with an Inform, not %s' % acs_http_request.cwmp_rpc_method 
                acs_session.acs_log(message)
                return HttpResponseBadRequest(message)
 
        ### initialize a variable
        empty_response=False
        ### first things first, do we have a body in the http request?
        if request.body:
            if acs_http_request.cwmp_rpc_method in settings.CWMP_ACS_VALID_RPC_METHODS:
                ####################################################################################################
                acs_session.acs_log('the ACS client %s is calling a valid RPC method on the ACS server: %s' % (ip, acs_http_request.cwmp_rpc_method))

                ### get SOAP response envelope
                root, body = get_soap_envelope(acs_http_request.cwmp_id, acs_session)

                ### set a few variables used when saving the HTTP response to db
                response_cwmp_rpc_method = '%sResponse' % acs_http_request.cwmp_rpc_method
                response_cwmp_id = acs_http_request.cwmp_id

                ### parse the soap request (which ACS RPC method is the CPE calling?)
                if acs_http_request.cwmp_rpc_method == 'Inform':
                    ### get Inform xml element
                    inform = soap_body.find('cwmp:Inform', acs_session.soap_namespaces)

                    ### determine which data model version this device is using
                    datamodel, created = CwmpDataModel.objects.get_or_create(
                        name=acs_session.determine_data_model(inform)
                    )
                    acs_session.acs_log("ACS client is using data model %s" % datamodel)
                    acs_session.root_data_model = datamodel

                    #########################################################################
                    ### get deviceid element from Inform request
                    deviceid = inform.find('DeviceId')
                    if deviceid is None:
                        message = 'Invalid Inform, DeviceID missing from request %s' % request
                        acs_session.acs_log(message)
                        return HttpResponseBadRequest(message)

                    serial = deviceid.find('SerialNumber').text
                    if not serial:
                        message = 'Invalid Inform, SerialNumber missing from request %s' % request
                        acs_session.acs_log(message)
                        return HttpResponseBadRequest(message)

                    vendor = deviceid.find('Manufacturer').text
                    if not vendor:
                        message = 'Invalid Inform, Manufacturer missing from request %s' % request
                        acs_session.acs_log(message)
                        return HttpResponseBadRequest(message)

                    model = deviceid.find('ProductClass').text
                    if not model:
                        message = 'Invalid Inform, ProductClass missing from request %s' % request
                        acs_session.acs_log(message)
                        return HttpResponseBadRequest(message)

                    oui = deviceid.find('OUI').text
                    if not oui:
                        message = 'Invalid Inform, OUI missing from request %s' % request
                        acs_session.acs_log(message)
                        return HttpResponseBadRequest(message)

                    ### find or create acs devicevendor (using Manufacturer and OUI)
                    acs_devicevendor, created = AcsDeviceVendor.objects.get_or_create(
                        name = vendor,
                        oui = oui,
                    )

                    ### find or create acs devicetype (using ProductClass)
                    acs_devicemodel, created = AcsDeviceModel.objects.get_or_create(
                        vendor = acs_devicevendor,
                        name = model,
                    )

                    ### find or create acs device (using serial number and acs devicetype)
                    acs_device, created = AcsDevice.objects.get_or_create(
                        model = acs_devicemodel,
                        serial = serial
                    )

                    ### set latest session result to False and increase inform count
                    acs_device.acs_latest_session_result = False
                    acs_device.acs_inform_count = F('acs_inform_count') + 1
                    acs_device.save()
 
                    # save acs_device to acs_session
                    acs_session.acs_device = acs_device
                    acs_session.save()

                    # attempt acs device association
                    if not acs_device.get_related_device():
                        acs_device.associate_with_related_device()

                    if not acs_device.acs_xmpp_password:
                        acs_device.create_xmpp_user()

                    if not acs_device.acs_connectionrequest_password:
                        acs_device.create_connreq_password()

                    if not acs_session.get_inform_eventcodes(inform, acs_http_request):
                        # the event section is missing from this Inform
                        return HttpResponseBadRequest()

                    #########################################################
                    # refresh from db to make any changes above visible
                    acs_device.refresh_from_db()

                    # if this acs device is associated with a real device we can call that devices verify_acs_client_ip() method
                    # and possibly mark this acs session as client_ip_verified=True (which is required before we give out any secrets like ssid in the session)
                    if acs_device.get_related_device():
                        ### run acs pre-ip-verified session hook
                        acs_device.get_related_device().acs_session_pre_verify_hook()

                        # set acs_session.client_ip_verified based on the outcome of verify_acs_client_ip(acs_session.client_ip) 
                        acs_session.client_ip_verified = acs_device.get_related_device().verify_acs_client_ip(acs_session.client_ip)
                        message = "client_ip_verified set to %s after running acs_device.get_related_device().verify_acs_client_ip(%s)" % (acs_session.client_ip_verified, acs_session.client_ip)
                        acs_session.acs_log(message)
                        acs_session.save()

                        ### run acs post-ip-verified session hook
                        acs_device.get_related_device().acs_session_post_verify_hook()

                        # refresh from db to make any changes above visible
                        acs_device.refresh_from_db()

                    ##########################################################
                    ### this is a good place to check for different Inform EventCodes or use
                    ### other data from the Inform

                    # first we clean up any old unprocessed automatic jobs.
                    # these might be lingering from earlier sessions that may have failed (for any number of reasons)
                    deleted, info = acs_session.acs_device.acs_queue_jobs.filter(automatic=True, processed=False).delete()
                    if deleted:
                        acs_session.acs_log("Cleanup: Deleted %s old unprocessed automatic AcsQueueJobs for this device" % deleted)

                    ### get parameterlist from the Inform payload
                    parameterlist = inform.find('ParameterList')

                    ### update current_config_level from Device.ManagementServer.ParameterKey
                    parameterkey = get_value_from_parameterlist(parameterlist, acs_session.get_acs_parameter_name('django_acs.acs.parameterkey'))
                    if not parameterkey:
                        acs_device.current_config_level = None
                    else:
                        acs_device.current_config_level = parse_datetime(parameterkey)

                    ### update latest_inform time
                    acs_device.acs_latest_inform = timezone.now()

                    ### update current_software_version
                    acs_device.current_software_version = get_value_from_parameterlist(parameterlist, acs_session.get_acs_parameter_name('django_acs.deviceinfo.softwareversion'))

                    ### save acs device
                    acs_device.save()

                    ###############################################
                    ### This is where we do things we want do _after_ an Inform session.
                    ### Queue jobs here before sending InformResponse and they will be run in the same session.

                    # queue GetParameterNames, GetParameterValues, GetParameterAttributes
                    if not acs_session.collect_device_info("Collecting information triggered by Inform"):
                        # unable to queue neccesary job
                        return HttpResponseServerError()

                    ## Queue a firmware upgrade job?
                    if not acs_session.device_firmware_upgrade():
                        # we wanted to queue a firmware upgrade job, but failed
                        return HttpResponseServerError()

                    ###############################################
                    ### we are done processing the Inform RPC request, and ready to return the InformResponse, 
                    ### so add the outer response element
                    cwmp = etree.SubElement(body, nse('cwmp', 'InformResponse'))
                    ### add the inner response elements, without namespace (according to cwmp spec!)
                    maxenv = etree.SubElement(cwmp, 'MaxEnvelopes')
                    maxenv.text = '1'

                elif acs_http_request.cwmp_rpc_method == 'TransferComplete':
                    ### handle TransferComplete RPC call
                    cwmp = etree.SubElement(body, nse('cwmp', 'TransferCompleteResponse'))

                else:
                    message = 'Unimplemented cwmp method %s called by the client %s' % (acs_http_request.cwmp_rpc_method, acs_device)
                    acs_session.acs_log(message)
                    return HttpResponseBadRequest(message)

                #####################################################################################################
                ### we are done processing the http request, put HTTP response together
                output = etree.tostring(root, encoding='utf-8', xml_declaration=True)
                response = HttpResponse(output, content_type='text/xml; charset=utf-8')

                ### save the HTTP response
                acs_http_response = AcsHttpResponse.objects.create(
                    http_request=acs_http_request,
                    fk_body=create_xml_document(xml=response.content),
                    cwmp_id=response_cwmp_id,
                    soap_element="{%s}%s" % (acs_session.soap_namespaces['cwmp'], response_cwmp_rpc_method),
                    rpc_response_to=acs_http_request,
                )
                acs_session.acs_log("responding to CPE %s with %s" % (acs_session.acs_device, response_cwmp_rpc_method))

            elif acs_http_request.cwmp_rpc_method and acs_http_request.cwmp_rpc_method[:-8] in settings.CWMP_CPE_VALID_RPC_METHODS:
                #####################################################################################################
                acs_session.acs_log('the CPE %s is responding to an RPC call from the ACS: %s' % (acs_session.acs_device, acs_http_request.cwmp_rpc_method))
                ### first link this http request to the related rpc request (which is in a http response),
                ### find it by looking for the same rpc method and cwmp id in http responses in this acs session
                match = False
                for httpresponse in acs_session.acs_http_responses:
                    if httpresponse.cwmp_rpc_method == acs_http_request.cwmp_rpc_method[:-8] and httpresponse.cwmp_id == acs_http_request.cwmp_id:
                        acs_http_request.rpc_response_to = httpresponse
                        acs_http_request.save()
                        match = True
                if not match:
                    message = 'Unable to find the HTTP response containing the RPC request being responded to :('
                    acs_session.acs_log(message)
                    return HttpResponseServerError(message)

                ### parse the cwmp object from the soap body
                rpcresponsexml = soap_body.find('cwmp:%s' % acs_http_request.cwmp_rpc_method, acs_session.soap_namespaces)

                if acs_http_request.cwmp_rpc_method == 'GetParameterNamesResponse':
                    ### do nothing for now, the response will be used when the GetParameterValuesResponse comes in later
                    pass

                elif acs_http_request.cwmp_rpc_method == 'GetParameterValuesResponse':
                    # nothing here for now
                    pass

                elif acs_http_request.cwmp_rpc_method == 'GetParameterAttributesResponse':
                    # this is a GetParameterAttributesResponse, attempt to update the device acs parameters
                    if acs_session.acs_device.update_acs_parameters(acs_http_request):
                        #################################################################################################
                        ### this is where we do things to and with the recently fetched acs parameters from the device,
                        ### like configuring the device or handling user config changes
                        ### Queue jobs here before sending GetParameterAttributesResponse and they will be run in the same session.

                        # extract device uptime from acs_device.acs_parameters and save it to acs_session.device_uptime
                        acs_session.update_device_uptime()

                        # check if we need to call the handle_user_config_changes() method on the acs_device,
                        # we only check for user changes if a device has been configured by us already, and doesn't need any more config at the moment
                        if acs_session.acs_device.current_config_level and acs_session.acs_device.current_config_level > acs_session.acs_device.get_desired_config_level():
                            # device is already configured, and doesn't need additional config from us right now, so check if the user changed anything on the device, and act accordingly
                            acs_session.acs_device.handle_user_config_changes()

                        # refresh to get any changes from above
                        acs_session.refresh_from_db()

                        # if this device has been reconfigured in this session we collect data again,
                        # if not, we reconfigure it if needed
                        if acs_session.configuration_done:
                            # device has been configured, so collect data again so we have the latest (unless we have already done so)
                            if not acs_session.post_configuration_collection_done:
                                if not acs_session.collect_device_info(reason="Device has been reconfigured"):
                                    acs_session.acs_log("Unable to queue one or more jobs to collect info after configuration")
                                    return HttpResponseServerError()
                        else:
                            # this device has not been configured in this ACS session. This is where we check if we need to configure it now.
                            # acs_session.configure_device returns False if there was a problem configuring the device, and true if
                            # the device was configured, or did not need to be configured
                            if not acs_session.configure_device():
                                # there was a problem creating configure jobs for the device
                                return HttpResponseServerError()

                elif acs_http_request.cwmp_rpc_method == 'GetRPCMethodsResponse':
                    pass

                elif acs_http_request.cwmp_rpc_method == 'SetParameterValuesResponse':
                    ### find status
                    status = rpcresponsexml.find('Status').text
                    if status != '0':
                        ### ACS client failed to apply all our settings, fuckery is afoot!
                        message = 'The ACS device %s failed to apply our SetParameterValues settings, something is wrong!' % acs_device
                        acs_session.acs_log(message)
                        return HttpResponseBadRequest(message)

                    ### find the parameterkey and update the acs_device so we know its current_config_level
                    ### since this is a SetParameterValuesResponse we will probably get settings.CWMP_CONFIG_INCOMPLETE_PARAMETERKEY_DATE here,
                    ### which is fine(tm)
                    parameterkey = acs_http_request.rpc_response_to.soap_body.find('cwmp:SetParameterValues', acs_session.soap_namespaces).find('ParameterKey').text
                    acs_session.acs_device.current_config_level = parse_datetime(parameterkey)

                elif acs_http_request.cwmp_rpc_method == 'SetParameterAttributesResponse':
                    ### find the parameterkey and update the acs_device so we know its current_config_level
                    parameterkey = acs_http_request.rpc_response_to.soap_body.find('cwmp:SetParameterAttributes', acs_session.soap_namespaces).find('ParameterKey').text
                    acs_session.acs_device.current_config_level = parse_datetime(parameterkey)
                    # in case we have a local desired_config_level on the acs device, unset it now as the configuration has been done
                    if acs_session.acs_device.desired_config_level:
                        acs_session.acs_device.desired_config_level = None
                    acs_session.acs_device.save()

                elif acs_http_request.cwmp_rpc_method == 'FactoryResetResponse':
                    empty_response=True

                ### we are done processing the clients response, do we have anything else?
                response = acs_http_request.get_response(empty_response=empty_response)
            else:
                '''
                ### TODO: insert some code to handle soapfault here so we dont hit the "Unknown cwmp object/method" bit below when a soapfault happens
                '''

                acs_session.acs_log('unknown cwmp object/method received from %s: %s' % (acs_session.acs_device, acs_http_request.cwmp_rpc_method))
                return HttpResponseBadRequest('unknown cwmp object/method received')

        else:
            # this http request has an empty body
            acs_session.acs_log('the CPE %s is done and posted an empty body to the ACS' % acs_session.acs_device)
            ### get a response for the client - if we have nothing queued it will be an empty response
            response = acs_http_request.get_response()

        ### all done, update the acs session with result before returning response
        acs_session.update_session_result()

        ### set the acs session cookie
        # we have to set this cookie manually because some stupid ACS client cannot parse expires in a http cookie
        # and Django always sets exipires in cookies, no even it the expires argument is set to None,
        # to be compatible with old IE clients yay
        #response.set_cookie(key='acs_session_id', value=max_age=60, expires=None, path='/')
        response['Set-Cookie'] = "acs_session_id=%s; Max-Age=60; Path=/" % hexid
        return response

