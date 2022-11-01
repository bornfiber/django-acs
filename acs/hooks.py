# External deps
import logging
import uuid
from lxml import etree
import yaml

# Dajngo deps
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.conf import settings

# Django model deps
from django.db.models import F
from .models import AcsDeviceVendor, AcsDeviceModel, AcsDevice, CwmpDataModel

from .utils import get_value_from_parameterlist, create_xml_document
from .response import nse, get_soap_envelope
from .conf import acs_settings

logger = logging.getLogger("django_acs.%s" % __name__)


def process_inform(acs_http_request, hook_state):
    acs_session = acs_http_request.acs_session
    acs_device = acs_session.acs_device

    # Check the hook_state
    if (
        acs_http_request.cwmp_rpc_method == "Inform"
        and "inform_received" in hook_state.keys()
    ):
        # If we receive a second Inform in the same session, signal this as an error.
        logger.info(f"{acs_session}: We have received an inform already in this sesson")
        hook_state["inform_multiple_error"] = str(timezone.now())
        return False, None, hook_state

    elif "inform_done" in hook_state.keys():
        # The inform is done.
        # Do nothing.
        return None, None, hook_state

    elif "inform_received" in hook_state.keys() and acs_http_request.soap_body is False:
        # This is the empty post that indicates that the inform phase is done.
        # Do nothing, and mark the inform as done.
        hook_state["inform_done"] = str(timezone.now())
        return None, None, hook_state

    elif acs_http_request.cwmp_rpc_method == "TransferComplete":
        logger.info(f"{acs_session}: {acs_device} sent a TransferComplete message.")

        # Inform processed OK, prepare a response
        root, body = get_soap_envelope(acs_http_request.cwmp_id, acs_session)
        cwmp = etree.SubElement(body, nse("cwmp", "TransferCompleteResponse"))
        # add the inner response elements, without namespace (according to cwmp spec!)
        maxenv = etree.SubElement(cwmp, "MaxEnvelopes")
        maxenv.text = "1"
        hook_state["transfer_complete"] = str(timezone.now())
        return root, body, hook_state

    elif acs_http_request.cwmp_rpc_method != "Inform":
        # If we receive anything that is not an inform, throw an error.
        logger.info(
            f"{acs_session}: The session must begin with an inform. Request {acs_http_request} is not an inform."
        )
        return False, None, hook_state

    # If we make to here, we process the inform.
    # A session has to begin with an inform, so if we get anything else we throw an error.

    # get Inform xml element
    inform = acs_http_request.soap_body.find("cwmp:Inform", acs_session.soap_namespaces)

    # Get the INFORM eventcodes
    eventcodes = get_inform_eventcodes(inform)
    if not eventcodes:
        logger.info(f"Did not receive any eventcodes. Killing session.")
        return False, None, hook_state
    acs_session.inform_eventcodes = eventcodes
    logger.info(f"{acs_session.tag}: Got INFORM eventcodes %s" % ",".join(eventcodes))

    # determine which data model version this device is using
    datamodel, created = CwmpDataModel.objects.get_or_create(
        name=acs_http_request.acs_session.determine_data_model(inform)
    )
    logger.info(f"{acs_session}: ACS client is using data model %s" % datamodel)
    acs_session.root_data_model = datamodel
    root_object = acs_session.root_data_model.root_object

    logger.info(f"ROOT OBJECT: {root_object}")

    deviceid = inform.find("DeviceId")
    mandatory_inform_fields = ["SerialNumber", "Manufacturer", "ProductClass", "OUI"]
    for inform_field in mandatory_inform_fields:
        field_value = deviceid.find(inform_field)
        print(f'Testing field {inform_field} it is "{field_value.text}"')
        if field_value is None or field_value.text == "":
            message = (
                f"{acs_session}: Invalid Inform, {inform_field} missing from request."
            )
            logger.info(message)
            return False, None, hook_state

    #########################################################################
    ### get deviceid element from Inform request

    # find or create acs devicevendor (using Manufacturer and OUI)
    acs_devicevendor, created = AcsDeviceVendor.objects.get_or_create(
        name__iexact=deviceid.find("Manufacturer").text,
        oui=deviceid.find("OUI").text,
        defaults={
            "name": deviceid.find("Manufacturer").text,
        },
    )

    # find or create acs devicetype (using ProductClass)
    acs_devicemodel, created = AcsDeviceModel.objects.get_or_create(
        vendor=acs_devicevendor,
        name__iexact=str(deviceid.find("ProductClass").text),
        defaults={
            "name": str(deviceid.find("ProductClass").text),
        },
    )

    # find or create acs device (using serial number and acs devicetype)
    acs_device, created = AcsDevice.objects.get_or_create(
        model=acs_devicemodel, serial=deviceid.find("SerialNumber").text
    )

    # set latest session result to False and increase inform count
    acs_device.acs_latest_session_result = False
    acs_device.acs_inform_count = F("acs_inform_count") + 1

    # Update acs_device data
    # get parameterlist from the Inform payload
    parameterlist = inform.find("ParameterList")

    ### update current_config_level from Device.ManagementServer.ParameterKey
    parameterkey = get_value_from_parameterlist(
        parameterlist, f"{root_object}.ManagementServer.ParameterKey"
    )
    if not parameterkey:
        acs_device.current_config_level = None
    else:
        acs_device.current_config_level = parse_datetime(parameterkey)

    # update latest_inform time
    acs_device.acs_latest_inform = timezone.now()

    # update current_software_version
    acs_device.current_software_version = get_value_from_parameterlist(
        parameterlist, f"{root_object}.DeviceInfo.SoftwareVersion"
    )

    logger.info(
        get_value_from_parameterlist(
            parameterlist, f"{root_object}.DeviceInfo.SoftwareVersion"
        )
    )

    # Reset the firmware_only flag, when a Boot is detected
    if "1 BOOT" in acs_session.inform_eventcodes:
        acs_device.firmware_only = False

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

    # Inform processed OK, prepare a response
    root, body = get_soap_envelope(acs_http_request.cwmp_id, acs_session)
    cwmp = etree.SubElement(body, nse("cwmp", "InformResponse"))
    ### add the inner response elements, without namespace (according to cwmp spec!)
    maxenv = etree.SubElement(cwmp, "MaxEnvelopes")
    maxenv.text = "1"

    hook_state["inform_received"] = str(timezone.now())
    return root, body, hook_state


def configure_xmpp(acs_http_request, hook_state):
    # Everyone GETS XMPP config if the configkey is empty.
    acs_session = acs_http_request.acs_session
    acs_device = acs_session.acs_device

    if "hook_done" in hook_state.keys():
        return None, None, hook_state

    # Process responses section
    if acs_http_request.cwmp_rpc_method == "GetParameterNamesResponse":
        logger.info(
            f"{acs_session.tag}/{acs_device}: Received GetParameterNamesResponse"
        )
        if (
            "pending_cwmp_id" in hook_state.keys()
            and acs_http_request.cwmp_id == "configure_xmpp_get"
        ):
            logger.info(
                f"{acs_session.tag}/{acs_device}: Received GetParameterNamesResponse and cwmp_id matches."
            )
            if "discovered_params" not in hook_state.keys():
                hook_state["discovered_params"] = {}
            # Process the response
            for param_info_struct in acs_http_request.soap_body.findall(
                ".//ParameterInfoStruct"
            ):
                key = param_info_struct.find("Name").text
                writeable = param_info_struct.find("Writable").text
                hook_state["discovered_params"][key] = writeable

                logger.info(
                    f"{acs_session.tag}/{acs_device}: Added paramter {key} to discovered_params."
                )

            hook_state["pending_cwmp_id"] = None

    if "get_done" not in hook_state.keys():
        root, body = _cwmp_GetParameterNames_soap(
            "InternetGatewayDevice.XMPP.Connection.", "configure_xmpp_get", acs_session
        )
        hook_state["get_done"] = str(timezone.now())
        hook_state["pending_cwmp_id"] = "configure_xmpp_get"
        return root, body, hook_state

    if not "get2_done" in hook_state.keys():
        root, body = _cwmp_GetParameterNames_soap(
            "InternetGatewayDevice.ManagementServer.", "configure_xmpp_get", acs_session
        )
        hook_state["get2_done"] = str(timezone.now())
        hook_state["pending_cwmp_id"] = "configure_xmpp_get"
        return root, body, hook_state

    if acs_http_request.cwmp_rpc_method == "AddObjectResponse":
        if acs_http_request.cwmp_id == hook_state["addobject"]["pending_cwmp_id"]:
            key = hook_state["addobject"]["key"]
            wanted_instance = hook_state["addobject"]["wanted_index"]
            logger.info(
                f"{acs_session.tag}/{acs_device}: Got AddObjectResponse to process."
            )

            instance_number = acs_http_request.soap_body.find(".//InstanceNumber").text
            print(f"Added instance:{key}{instance_number}, calling GetParameterNames")
            if int(instance_number) > int(wanted_instance):
                print("Killing session, instance overrun.")
                return None, None, hook_state

            # Rescan
            hook_state["pending_cwmp_id"] = "configure_xmpp_get"
            root, body = _cwmp_GetParameterNames_soap(
                f"{key}{instance_number}.", "configure_xmpp_get", acs_session
            )
            return root, body, hook_state

    device_config = {}
    device_config["django_acs.acs.informinterval"] = acs_settings.INFORM_INTERVAL
    # add acs client xmpp settings (only if we have an xmpp account for this device)
    if acs_device.acs_xmpp_password:
        device_config["django_acs.acs.xmpp_server"] = settings.ACS_XMPP_SERVERTUPLE[0]
        device_config[
            "django_acs.acs.xmpp_server_port"
        ] = settings.ACS_XMPP_SERVERTUPLE[1]
        device_config["django_acs.acs.xmpp_connection_enable"] = True
        device_config[
            "django_acs.acs.xmpp_connection_username"
        ] = acs_device.acs_xmpp_username
        device_config[
            "django_acs.acs.xmpp_connection_password"
        ] = acs_device.acs_xmpp_password
        device_config[
            "django_acs.acs.xmpp_connection_domain"
        ] = (
            settings.ACS_XMPP_DOMAIN
        )  # all ACS clients connect to the same XMPP server domain for now
        device_config["django_acs.acs.xmpp_connection_usetls"] = False

    # set connectionrequest credentials?
    if acs_device.acs_connectionrequest_username:
        device_config[
            "django_acs.acs.connection_request_user"
        ] = acs_device.acs_connectionrequest_username
        device_config[
            "django_acs.acs.connection_request_password"
        ] = acs_device.acs_connectionrequest_password

    # Generate the config
    yaml_struct = load_form_yaml(acs_device, "xmpp_template")
    config_dict = merge_config_template_dict(yaml_struct, device_config)

    # Test if we need to call Addobject
    addobject_list = get_addobject_list(config_dict, hook_state["discovered_params"])

    logger.info(f"{acs_session.tag}/{acs_device}: Addlist is {addobject_list}")
    # If we have objects that need to be added, do so now.
    if addobject_list:
        logger.info(f"{acs_session}: Adding object {addobject_list[0][0]}")
        response_cwmp_id = uuid.uuid4().hex
        hook_state["addobject"] = {
            "pending_cwmp_id": response_cwmp_id,
            "key": addobject_list[0][0],
            "wanted_index": addobject_list[0][1],
        }

        # Add the first object in the addobject_list
        root, body = _cwmp_AddObject_soap(
            addobject_list[0][0], "hejsa", response_cwmp_id, acs_session
        )
        return root, body, hook_state

    # Set the parameters
    logger.info(f"{acs_session.tag}/{acs_device}: Configuring XMMP")
    cwmp_id = uuid.uuid4().hex
    parameter_key = str(acs_device.current_config_level)
    root, body = _cwmp_SetParameterNames_soap(
        config_dict, parameter_key, cwmp_id, acs_session
    )

    hook_state["hook_done"] = str(timezone.now())
    return root, body, hook_state


def track_parameters(acs_http_request, hook_state):
    acs_session = acs_http_request.acs_session
    acs_device = acs_session.acs_device

    if "hook_done" in hook_state.keys():
        logger.info(f"{acs_session.tag}/{acs_device}: track_paramters is done")
        return None, None, hook_state

    # If we have a peningd_cwmp_id, try to mach it
    if (
        "pending_cwmp_id" in hook_state.keys()
        and acs_http_request.cwmp_id == hook_state["pending_cwmp_id"]
    ):
        # If we get a GetParamterValuesResponse
        if acs_http_request.cwmp_rpc_method == "GetParameterValuesResponse":
            logger.info(
                f"{acs_session.pk}/{acs_device}: Processing track_parameters GetParameterValuesResponse."
            )

            # Save the Parametervalues
            root = etree.Element("DjangoAcsParameterCache")
            paramcount = 0
            for param in (
                acs_http_request.soap_body.find(
                    "cwmp:GetParameterValuesResponse", acs_session.soap_namespaces
                )
                .find("ParameterList")
                .getchildren()
            ):
                paramcount += 1

                # Add empty writeable element.
                writable = etree.Element("Writable")
                writable.text = ""
                param.append(writable)

                root.append(param)

            logger.info(
                f"{acs_session.tag}/{acs_device}: Processed {paramcount} paramters."
            )
            ### alright, update the ACS device with the new information.
            acs_device.acs_parameters = etree.tostring(
                root, xml_declaration=True
            ).decode("utf-8", "ignore")
            acs_device.acs_parameters_time = timezone.now()

            hook_state["hook_done"] = True
            return None, None, hook_state

        # If we get a fault, and the faultcode is 9000/Method not supported, we flag the acs_device as firmware_only
        if (
            acs_http_request.soap_element_tuple[1] == "Fault"
            and acs_http_request.cwmp_id == hook_state["pending_cwmp_id"]
        ):
            faultcodes = [
                f.text for f in acs_http_request.soap_body.findall(".//FaultCode")
            ]
            if "9000" in faultcodes:
                logger.info(
                    f"{acs_http_request.pk}/{acs_device}: Setting firmware_only. Got a 9000 faultcode."
                )
                acs_device.firmware_only = True
                hook_state["hook_done"] = True
                return None, None, hook_state

    if "tracked_parameters" not in hook_state.keys():
        tracked_parameters = load_tracked_parameters(acs_device)
        cwmp_id = uuid.uuid4().hex
        logger.info(f'{acs_session.tag}: tracked_parameters: "{tracked_parameters}"')
        hook_state["tracked_parameters"] = tracked_parameters
        hook_state["pending_cwmp_id"] = cwmp_id
        root, body = _cwmp_GetPrameterValues_soap(
            tracked_parameters, cwmp_id, acs_session
        )
        return root, body, hook_state

    return None, None, hook_state


def get_cpe_rpc_methods(acs_http_request, hook_state):
    acs_session = acs_http_request.acs_session
    acs_device = acs_session.acs_device

    if "hook_done" in hook_state.keys():
        return None, None, hook_state

    hook_state["hook_done"] = str(timezone.now())
    root, body = cwmp_obj = cwmp_GetRPCMethods(acs_session)
    return root, body, hook_state


def _device_config(acs_http_request, hook_state):
    acs_session = acs_http_request.acs_session
    acs_device = acs_session.acs_device

    # root,body = _cwmp_FactoryReset_soap(acs_session)
    # return root,body,hook_state

    if "hook_done" in hook_state.keys():
        print(f"_device_config alredy done")
        return None, None, hook_state

    if "no_related_device" in hook_state.keys():
        print(f"_device_config has no related_device.")
        return None, None, hook_state

    if not acs_session.client_ip_verified:
        logger.info(
            f"{acs_session.tag}/{acs_device}: Not configuring, client IP is not verified."
        )
        hook_state["hook_done"] = str(timezone.now())
        return None, None, hook_state

    if acs_device.current_config_level == acs_device.desired_config_level:
        logger.info(
            f"{acs_session.tag}/{acs_device}: current_config_level == desired_config_level, not doing config."
        )
        hook_state["hook_done"] = str(timezone.now())
        return None, None, hook_state

    # Get the real associated device if any.
    related_device = acs_device.get_related_device()

    if not related_device:
        hook_state["no_related_device"] = True
        logger.info(f"{acs_session.tag}: {acs_device} has no related related_device.")
        return None, None, hook_state

    # Process incoming GetParameterNamesResponse
    if acs_http_request.cwmp_rpc_method == "GetParameterNamesResponse":
        if acs_http_request.cwmp_id == hook_state["pending_cwmp_id"]:
            logger.info(f"{acs_session.tag}: Got response to process.")

            for param_info_struct in acs_http_request.soap_body.findall(
                ".//ParameterInfoStruct"
            ):
                key = param_info_struct.find("Name").text
                writeable = param_info_struct.find("Writable").text
                hook_state["discovered_param_names"][key] = writeable

    if acs_http_request.cwmp_rpc_method == "AddObjectResponse":
        if acs_http_request.cwmp_id == hook_state["addobject"]["pending_cwmp_id"]:
            key = hook_state["addobject"]["key"]
            wanted_instance = hook_state["addobject"]["wanted_index"]
            logger.info(f"{acs_session.tag}: Got AddObjectResponse to process.")

            instance_number = acs_http_request.soap_body.find(".//InstanceNumber").text
            print(f"Added instance:{key}{instance_number}, calling GetParameterNames")
            if int(instance_number) > int(wanted_instance):
                print("Killing session, instance overrun.")
                return None, None, hook_state

            # Rescan
            response_cwmp_id = uuid.uuid4().hex
            hook_state["pending_cwmp_id"] = response_cwmp_id
            root, body = _cwmp_GetParameterNames_soap(
                f"{key}{instance_number}.", response_cwmp_id, acs_session
            )
            return root, body, hook_state

    # GetParamterNames, get the entire tree.
    if "getnames_sent" not in hook_state.keys():
        hook_state["getnames_sent"] = str(timezone.now())
        # Initiliaze&FLush the discovered_param_names dict.
        hook_state["discovered_param_names"] = {}

        response_cwmp_id = uuid.uuid4().hex
        hook_state["pending_cwmp_id"] = response_cwmp_id
        root, body = _cwmp_GetParameterNames_soap("", response_cwmp_id, acs_session)

        return root, body, hook_state

    # Build the device_config dict
    device_config = related_device.get_acs_config()

    # Add InformInterval
    device_config["django_acs.acs.informinterval"] = acs_settings.INFORM_INTERVAL

    # add acs client xmpp settings (only if we have an xmpp account for this device)
    if acs_device.acs_xmpp_password:
        device_config["django_acs.acs.xmpp_server"] = settings.ACS_XMPP_SERVERTUPLE[0]
        device_config[
            "django_acs.acs.xmpp_server_port"
        ] = settings.ACS_XMPP_SERVERTUPLE[1]
        device_config["django_acs.acs.xmpp_connection_enable"] = True
        device_config[
            "django_acs.acs.xmpp_connection_username"
        ] = acs_device.acs_xmpp_username
        device_config[
            "django_acs.acs.xmpp_connection_password"
        ] = acs_device.acs_xmpp_password
        device_config[
            "django_acs.acs.xmpp_connection_domain"
        ] = (
            settings.ACS_XMPP_DOMAIN
        )  # all ACS clients connect to the same XMPP server domain for now
        device_config["django_acs.acs.xmpp_connection_usetls"] = False

    # set connectionrequest credentials?
    if acs_device.acs_connectionrequest_username:
        device_config[
            "django_acs.acs.connection_request_user"
        ] = acs_device.acs_connectionrequest_username
        device_config[
            "django_acs.acs.connection_request_password"
        ] = acs_device.acs_connectionrequest_password

    # Generate the config
    template_dict = _parse_config_template(
        acs_device.model.config_template, acs_session.inform_eventcodes
    )
    config_dict = _merge_config_template(template_dict, device_config)

    # Test if we need to call Addobject
    addobject_list = get_addobject_list(
        config_dict, hook_state["discovered_param_names"]
    )

    # If we have objects that need to be added, do so now.
    if addobject_list:
        logger.info(f"{acs_session}: Adding object {addobject_list[0][0]}")
        response_cwmp_id = uuid.uuid4().hex
        hook_state["addobject"] = {
            "pending_cwmp_id": response_cwmp_id,
            "key": addobject_list[0][0],
            "wanted_index": addobject_list[0][1],
        }

        # Add the first object in the addobject_list
        root, body = _cwmp_AddObject_soap(
            addobject_list[0][0], "hejsa", response_cwmp_id, acs_session
        )
        return root, body, hook_state

    # Set the parameters
    cwmp_id = uuid.uuid4().hex
    parameter_key = str(acs_device.desired_config_level)
    root, body = _cwmp_SetParameterNames_soap(
        config_dict, parameter_key, cwmp_id, acs_session
    )

    hook_state["hook_done"] = str(timezone.now())
    return root, body, hook_state


def _preconfig(acs_http_request, hook_state):
    # Preconfig is given to all ACS devices that have a physical device. Regardless of IP address validation.
    acs_session = acs_http_request.acs_session
    acs_device = acs_session.acs_device
    related_device = acs_device.get_related_device()

    if "hook_done" in hook_state.keys():
        return None, None, hook_state

    if acs_device.current_config_level == acs_device.desired_config_level:
        logger.info(
            f"{acs_session.tag}/{acs_device}: current_config_level == desired_config_level, not doing preconfig."
        )
        hook_state["hook_done"] = str(timezone.now())
        return None, None, hook_state

    if related_device:
        logger.info(
            f"{acs_session}: Applying preconfig to {acs_device} as it is related with {acs_device.get_related_device()}"
        )
    else:
        logger.info(
            f"{acs_session}: Not applying preconfig to {acs_device} as it is not in our inventory."
        )
        hook_state["hook_done"] = str(timezone.now())
        return None, None, hook_state

    # Generate the config
    template_dict = _parse_config_template(
        acs_device.model.preconfig_template, acs_session.inform_eventcodes
    )

    if related_device:
        device_config = related_device.get_acs_config()
    else:
        device_config = {}

    # Add InformInterval
    device_config["django_acs.acs.informinterval"] = acs_settings.INFORM_INTERVAL

    # add acs client xmpp settings (only if we have an xmpp account for this device)
    if acs_device.acs_xmpp_password:
        device_config["django_acs.acs.xmpp_server"] = settings.ACS_XMPP_SERVERTUPLE[0]
        device_config[
            "django_acs.acs.xmpp_server_port"
        ] = settings.ACS_XMPP_SERVERTUPLE[1]
        device_config["django_acs.acs.xmpp_connection_enable"] = True
        device_config[
            "django_acs.acs.xmpp_connection_username"
        ] = acs_device.acs_xmpp_username
        device_config[
            "django_acs.acs.xmpp_connection_password"
        ] = acs_device.acs_xmpp_password
        device_config[
            "django_acs.acs.xmpp_connection_domain"
        ] = (
            settings.ACS_XMPP_DOMAIN
        )  # all ACS clients connect to the same XMPP server domain for now
        device_config["django_acs.acs.xmpp_connection_usetls"] = False

    # set connectionrequest credentials?
    if acs_device.acs_connectionrequest_username:
        device_config[
            "django_acs.acs.connection_request_user"
        ] = acs_device.acs_connectionrequest_username
        device_config[
            "django_acs.acs.connection_request_password"
        ] = acs_device.acs_connectionrequest_password

    ### END ###

    # Generate the config
    template_dict = _parse_config_template(
        acs_device.model.preconfig_template, acs_session.inform_eventcodes
    )
    config_dict = _merge_config_template(template_dict, device_config)

    # Set the parameters
    cwmp_id = uuid.uuid4().hex
    parameter_key = str(acs_device.current_config_level)
    root, body = _cwmp_SetParameterNames_soap(
        config_dict, parameter_key, cwmp_id, acs_session
    )

    hook_state["hook_done"] = str(timezone.now())
    return root, body, hook_state


""" HOOK HELPER FUNCTIONS """


def _add_pvs_type(element, key, value_type, value):
    struct = etree.SubElement(element, "ParameterValueStruct")
    nameobj = etree.SubElement(struct, "Name")
    nameobj.text = key
    valueobj = etree.SubElement(struct, "Value")

    if value_type == "boolean":
        valueobj.set(nse("xsi", "type"), "xsd:boolean")
        valueobj.text = str(value).lower()
    elif value_type == "unsignedInt":
        valueobj.set(nse("xsi", "type"), "xsd:unsignedInt")
        valueobj.text = str(int(value))
    elif value_type == "string":
        valueobj.set(nse("xsi", "type"), "xsd:string")
        valueobj.text = str(value)
    elif value_type == "int":
        valueobj.set(nse("xsi", "type"), "xsd:int")
        valueobj.text = str(int(value))

    return element


def _cwmp_SetParameterNames_soap(config_dict, ParameterKey, cwmp_id, acs_session):
    cwmp_obj = etree.Element(nse("cwmp", "SetParameterValues"))
    paramlist = etree.SubElement(cwmp_obj, "ParameterList")

    for param_key, (param_type, param_value) in config_dict.items():
        _add_pvs_type(paramlist, param_key, param_type, param_value)

    root, body = get_soap_envelope(cwmp_id, acs_session)
    body.append(cwmp_obj)

    paramlist.set(
        nse("soap-enc", "arrayType"), "cwmp:ParameterValueStruct[%s]" % len(paramlist)
    )
    paramkey = etree.SubElement(cwmp_obj, "ParameterKey")
    paramkey.text = ParameterKey
    return root, body


def _cwmp_GetParameterNames_soap(key, cwmp_id, acs_session, next_level=True):
    cwmp_obj = etree.Element(nse("cwmp", "GetParameterNames"))
    ### add the inner response elements, but without XML namespace (according to cwmp spec!)

    parampath = etree.SubElement(cwmp_obj, "ParameterPath")
    parampath.text = key
    nextlevel = etree.SubElement(cwmp_obj, "NextLevel")
    nextlevel.text = "0"

    root, body = get_soap_envelope(cwmp_id, acs_session)
    body.append(cwmp_obj)

    return root, body


def _cwmp_AddObject_soap(key, ParameterKey, cwmp_id, acs_session):
    cwmp_obj = etree.Element(nse("cwmp", "AddObject"))
    object_name = etree.SubElement(cwmp_obj, "ObjectName")
    object_name.text = key

    root, body = get_soap_envelope(cwmp_id, acs_session)
    body.append(cwmp_obj)

    paramkey = etree.SubElement(cwmp_obj, "ParameterKey")
    paramkey.text = ParameterKey
    return root, body


def _cwmp_GetPrameterValues_soap(key_list, cwmp_id, acs_session):
    # Create a list of unique paramters we want to get info for.
    get_list = []
    for new_key in sorted(key_list, key=len):
        found = False
        for inserted_key in get_list:
            if new_key.startswith(inserted_key):
                found = True
                break
        if not found:
            get_list.append(new_key)

    cwmp_obj = etree.Element(nse("cwmp", "GetParameterValues"))
    paramlist = etree.SubElement(cwmp_obj, "ParameterNames")

    for key in get_list:
        nameobj = etree.SubElement(paramlist, "string")
        nameobj.text = key

    paramlist.set(nse("soap-enc", "arrayType"), "xsd:string[%s]" % len(paramlist))
    root, body = get_soap_envelope(cwmp_id, acs_session)
    body.append(cwmp_obj)

    return root, body


def _cwmp_FactoryReset_soap(acs_session):
    cwmp_obj = etree.Element(nse("cwmp", "FactoryReset"))
    root, body = get_soap_envelope("FactoryResetId", acs_session)
    body.append(cwmp_obj)

    return root, body


def cwmp_GetRPCMethods(acs_session):
    cwmp_obj = etree.Element(nse("cwmp", "GetRPCMethods"))
    root, body = get_soap_envelope("FactoryResetId", acs_session)
    body.append(cwmp_obj)

    return root, body


def _parse_config_template(template, inform_eventcodes=[]):
    parsed_data = {}

    bootstrap = False
    if "0 BOOTSTRAP" in inform_eventcodes:
        bootstrap = True

    for line in template.splitlines():
        if line.startswith("#"):
            continue
        if line.isspace():
            continue
        if line == "":
            continue
        if line.startswith("!") and bootstrap:
            line = line[1:]
        elif line.startswith("!"):
            continue
        line_fields = [f.strip() for f in line.split("|")]
        if len(line_fields) == 4:
            param, param_type, config_key, param_default = line_fields
        elif len(line_fields) == 3:
            param, param_type, config_key = line_fields
            param_default = None

        else:
            logger.info(f'Unable to parse line "{line}"')
            continue

        parsed_data[param] = (param_type, config_key, param_default)

    return parsed_data


def get_addobject_list(config_dict, parameternames_dict):
    # Generate a set of Addobject calls if needed.
    addobject_set = set()

    config_keys = list(config_dict)
    parameternames_keys = list(parameternames_dict)

    missing_keys = set()

    # Iterate over each config_dict item at test if it exists
    # Skip config_keys that exist as exact matches.
    for config_key in config_dict.keys():
        if config_key not in parameternames_keys:
            missing_keys.add(config_key)

    print(f"Missing keys:{missing_keys}")
    # Process each missing config_key
    for config_key in missing_keys:
        config_key_elements = config_key.split(".")

        # Progressively lenghten configkey until we don't find a match anymore.
        for i in range(2, len(config_key_elements)):
            # If the last element is not an index, continue with the next length.
            if not config_key_elements[i - 1].isnumeric():
                continue

            # Construct the shortened config_key
            shortened_config_key = ".".join(config_key_elements[:i]) + "."
            # print(f"Testing: {shortened_config_key}")
            # If any item in paramternames_keys matches, continue to the next longer shortened_config_key
            if any(
                [key.startswith(shortened_config_key) for key in parameternames_keys]
            ):
                # print(f"Found {shortened_config_key}")
                continue

            # print("Missing: %s" % ".".join(config_key_elements[:i]) + ".")
            addobject_set.add(
                (
                    ".".join(config_key_elements[: i - 1]) + ".",
                    config_key_elements[i - 1],
                )
            )
            # print()
            break

    # Return a sorted list of missing keys.
    return sorted(addobject_set, key=len)


def get_inform_eventcodes(inform):
    # get Event element from Inform request
    event = inform.find("Event")
    if event is None:
        return []

    # get the EventCode(s) for this inform
    eventcodes = []
    for es in event.findall("EventStruct"):
        eventcodes.append(es.find("EventCode").text)

    return eventcodes


""" HELPER FUNCTIONS FOR CONFIGURATION LOADING """


def _merge_config_template(template_dict, config_dict):
    # Merge the template with the config from get_acs_config()
    # Merging rules
    # 1. If neither default value or configdict has a value, the paramter is dropped.
    # 2. If the configdict has no value the default is used.

    output_dict = {}
    for param in template_dict.keys():
        param_type, config_key, param_default = template_dict[param]
        if config_key == "" and param_default is not None:
            output_dict[param] = (param_type, param_default)
        elif config_key in config_dict.keys():
            output_dict[param] = (param_type, config_dict[config_key])
        elif param_default is not None:
            output_dict[param] = (param_type, param_default)

    return output_dict


def merge_config_template_dict(template_dict, config_dict):
    # Merge the template with the config from get_acs_config()
    # Merging rules
    # 1. If neither default value or configdict has a value, the paramter is dropped.
    # 2. If the configdict has no value the default is used.
    output_dict = {}

    for template_key, template_values_dict in template_dict.items():
        # If we don't have a type definition, skip the template key.
        logger.info(f"Merging {template_key}")
        if not "type" in template_values_dict.keys():
            continue
        # If we have a acs_config definition, try to assign from config_dict
        if "acs_config" in template_values_dict.keys():
            if template_values_dict["acs_config"] in config_dict.keys():
                output_dict[template_key] = (
                    template_values_dict["type"],
                    str(config_dict[template_values_dict["acs_config"]]),
                )
                continue
        # If we end up here, maybe we have a default value to assign
        if "default" in template_values_dict.keys():
            output_dict[template_key] = (
                template_values_dict["type"],
                template_values_dict["default"],
            )

    return output_dict


def load_tracked_parameters(acs_device):
    device_tracked_set = set()
    lines = acs_device.model.tracked_parameters.splitlines()
    for line in lines:
        if line == "":
            continue
        if line.startswith("#"):
            continue
        # if not line.endswith("."): continue

        device_tracked_set.add(line.strip())

    return list(device_tracked_set)


def load_form_yaml(acs_device, field_name, config_version="default"):
    acs_model = acs_device.model
    yaml_struct = yaml.load(getattr(acs_model, field_name))

    # Flatten the data
    flattened_yaml_struct = flatten_yaml_struct(yaml_struct[config_version])
    return flattened_yaml_struct


def flatten_yaml_struct(yaml_struct, key_path="", out_data={}):
    for k, v in yaml_struct.items():
        if isinstance(v, dict):
            new_key_path = ".".join([i for i in [key_path, k] if i])
            flatten_yaml_struct(v, new_key_path, out_data)
        else:
            if key_path not in out_data.keys():
                out_data[key_path] = {k: v}
            else:
                out_data[key_path][k] = v
    return out_data
