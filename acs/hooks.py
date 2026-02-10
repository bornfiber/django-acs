# External deps
import logging
import uuid
from lxml import etree
import yaml
from urllib.parse import urlparse

# Dajngo deps
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.conf import settings

# Django model deps
from django.db.models import F
from .models import AcsDeviceVendor, AcsDeviceModel, AcsDevice, CwmpDataModel
from django.core.exceptions import ObjectDoesNotExist

from .utils import get_value_from_parameterlist
from .response import nse, get_soap_envelope
from .conf import acs_settings

logger = logging.getLogger("django_acs.%s" % __name__)
logger.setLevel(logging.INFO)


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

    elif "hook_done" in hook_state.keys():
        # The inform is done.
        # Do nothing.
        logger.info(f"{acs_session}: Inform hook is already done.")
        return None, None, hook_state

    elif "inform_received" in hook_state.keys() and acs_http_request.soap_body is False:
        # This is the empty post that indicates that the inform phase is done.
        # Do nothing, and mark the inform as done.
        hook_state["hook_done"] = str(timezone.now())
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

    elif acs_http_request.cwmp_rpc_method == "GetRPCMethods":
        logger.info(f"{acs_session}: {acs_device} sent a GetRPCMethods message.")

        # Inform processed OK, prepare a response
        root, body = get_soap_envelope(acs_http_request.cwmp_id, acs_session)
        cwmp = etree.SubElement(body, nse("cwmp", "GetRPCMethodsResponse"))
        # add the inner response elements, without namespace (according to cwmp spec!)
        method_list = etree.SubElement(cwmp, "MethodList")
        for method in ["Inform", "GetRPCMethods", "TransferComplete"]:
            ele = etree.SubElement(method_list, "string")
            ele.text = method
        
        return root, body, hook_state

    elif acs_http_request.cwmp_rpc_method != "Inform":
        # If we receive anything that is not an inform, throw an error.
        logger.warning(
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
        logger.warning(
            f"Did not receive any eventcodes. Killing session. (client ip: {acs_session.client_ip}"
        )
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

    deviceid = inform.find("DeviceId")
    mandatory_inform_fields = ["SerialNumber", "Manufacturer", "ProductClass", "OUI"]
    for inform_field in mandatory_inform_fields:
        field_value = deviceid.find(inform_field)
        # logger.info(f"{acs_session}: Testing field {inform_field} it is \"{field_value.text}\"")
        if field_value is None or field_value.text is None or field_value.text == "":
            logger.warning(f"{acs_session}: Invalid Inform, {inform_field} missing from request. Killing session.")
            return False, None, hook_state

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

    # Try to find our ACS device, as a perfect match
    try:
        acs_device = AcsDevice.objects.get(model=acs_devicemodel, serial=deviceid.find("SerialNumber").text)
        logger.info(f"{acs_session}: matched to {acs_device}")
    except ObjectDoesNotExist:
        # If we do not have an AcsDevice, try to match without OUI and update model accordingly, instead of creating.
        acs_device, created = AcsDevice.objects.update_or_create(
            serial=str(deviceid.find("SerialNumber").text),
            model__name=str(deviceid.find("ProductClass").text),
            model__vendor__name=str(deviceid.find("Manufacturer").text),
            defaults={
                "model": acs_devicemodel,
            }
        )
        if created:
            logger.info(f"{acs_session}: created{acs_device}")
        else:
            logger.info(f"{acs_session}: Updated {acs_device} devicemodel to {acs_devicemodel}.")

    # set latest session result to False and increase inform count
    acs_device.acs_latest_session_result = False
    acs_device.acs_inform_count = F("acs_inform_count") + 1

    # Update acs_device data
    # get parameterlist from the Inform payload
    parameterlist = inform.find("ParameterList")

    # update connectionrequest_url
    connectionrequest_url = get_value_from_parameterlist(
        parameterlist, f"{root_object}.ManagementServer.ConnectionRequestURL"
    )
    acs_device.acs_connectionrequest_url = connectionrequest_url or ""

    # update current_config_level from Device.ManagementServer.ParameterKey
    parameterkey = get_value_from_parameterlist(
        parameterlist, f"{root_object}.ManagementServer.ParameterKey"
    )
    if not parameterkey:
        logger.warning(
            f"{acs_session.tag}/{acs_device}: Did not find parameterkey in inform."
        )
        acs_device.current_config_level = None
    else:
        acs_device.current_config_level = parse_datetime(parameterkey)
        logger.info(
            f"{acs_session.tag}/{acs_device}: Parameterkey in inform is {acs_device.current_config_level} ."
        )

    # update latest_inform time
    acs_device.acs_latest_inform = timezone.now()

    # update current_software_version
    acs_device.current_software_version = get_value_from_parameterlist(
        parameterlist, f"{root_object}.DeviceInfo.SoftwareVersion"
    )

    # Initialize the device hook_state to an empty dict if it is None
    if acs_device.hook_state is None:
        acs_device.hook_state = {}

    # Record the latest_access_domain
    acs_device.hook_state["latest_access_domain"] = acs_session.access_domain
    acs_device.hook_state["root_object"] = root_object
    # Save the acs_device
    acs_device.save()

    # save acs_device to acs_session
    acs_session.acs_device = acs_device
    acs_session.save()

    # attempt acs device association
    if not acs_device.get_related_device():
        acs_device.associate_with_related_device()

        # If the association was a success, we request a factory reset, unless the current session has eventcode BOOTSTRAP
        if acs_device.get_related_device() and "0 BOOTSTRAP" not in acs_session.inform_eventcodes:
            logger.info(f"{acs_session.tag}/{acs_device}: Sending FactoryReset, CPE device just associated without reporting 0 BOOTSTRAP.")
            acs_device.factory_default_request = True
            acs_device.save()

    if not acs_device.acs_xmpp_password:
        acs_device.create_xmpp_user()

    if not acs_device.acs_connectionrequest_password:
        acs_device.create_connreq_password()

    # Inform processed OK, prepare a response
    root, body = get_soap_envelope(acs_http_request.cwmp_id, acs_session)
    cwmp = etree.SubElement(body, nse("cwmp", "InformResponse"))
    # add the inner response elements, without namespace (according to cwmp spec!)
    maxenv = etree.SubElement(cwmp, "MaxEnvelopes")
    maxenv.text = "1"

    hook_state["inform_received"] = str(timezone.now())
    return root, body, hook_state


def configure_xmpp(acs_http_request, hook_state):
    acs_session = acs_http_request.acs_session
    acs_device = acs_session.acs_device

    # If the device model has no xmpp config (), we are done...
    device_config = get_device_config_dict(acs_device)
    config_template = load_from_yaml(acs_device, "xmpp_template", config_version=device_config.get("django_acs.acs_config_name"))

    root_object = acs_session.root_data_model.root_object

    if not config_template:
        logger.debug(
            f"{acs_session.tag}/{acs_device}: xmpp_config, device has no XMPP config template, hook is done."
        )
        hook_state["hook_done"] = str(timezone.now())
        return None, None, hook_state

    # Every device get at least a XMPP config either on boot or when config_level is out of sync or empty.

    if "1 BOOT" in acs_session.inform_eventcodes:
        logger.info(
            f"{acs_session.tag}/{acs_device}: xmpp_config, configuring beacause of BOOT."
        )
    elif acs_device.current_config_level is None:
        logger.info(
            f"{acs_session.tag}/{acs_device}: xmpp_config, configuring beacause current_config_level is None."
        )
    elif acs_device.get_desired_config_level() and acs_device.current_config_level == acs_device.get_desired_config_level():
        logger.debug(
            f"{acs_session.tag}/{acs_device}: xmpp_config, not configuring current_config_level == desired_config_level."
        )
        hook_state["hook_done"] = str(timezone.now())
        return None, None, hook_state
    elif acs_device.get_desired_config_level() is None:
        logger.info(
            f"{acs_session.tag}/{acs_device}: xmpp_config, not configuring no desired_config_level, and no other reason to configure."
        )
        hook_state["hook_done"] = str(timezone.now())
        return None, None, hook_state

    # Process responses section
    if acs_http_request.cwmp_rpc_method == "GetParameterNamesResponse":
        logger.info(
            f"{acs_session.tag}/{acs_device}: xmpp_config received GetParameterNamesResponse"
        )
        if (
            "pending_cwmp_id" in hook_state.keys()
            and acs_http_request.cwmp_id == "configure_xmpp_get"
        ):
            logger.info(
                f"{acs_session.tag}/{acs_device}: xmpp_config Received GetParameterNamesResponse and cwmp_id matches."
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

            hook_state["pending_cwmp_id"] = None

    if "get_done" not in hook_state.keys():
        root, body = _cwmp_GetParameterNames_soap(
            f"{root_object}.XMPP.Connection.", "configure_xmpp_get", acs_session
        )
        hook_state["get_done"] = str(timezone.now())
        hook_state["pending_cwmp_id"] = "configure_xmpp_get"
        return root, body, hook_state

    if "get2_done" not in hook_state.keys():
        root, body = _cwmp_GetParameterNames_soap(
            f"{root_object}.ManagementServer.", "configure_xmpp_get", acs_session
        )
        hook_state["get2_done"] = str(timezone.now())
        hook_state["pending_cwmp_id"] = "configure_xmpp_get"
        return root, body, hook_state

    if acs_http_request.cwmp_rpc_method == "AddObjectResponse":
        if acs_http_request.cwmp_id == hook_state["addobject"]["pending_cwmp_id"]:
            key = hook_state["addobject"]["key"]
            wanted_instance = hook_state["addobject"]["wanted_index"]
            logger.info(f"{acs_session.tag}/{acs_device}: Got AddObjectResponse to process.")

            instance_number = acs_http_request.soap_body.find(".//InstanceNumber").text
            logger.info(f"Added instance:{key}{instance_number}, calling GetParameterNames")
            if int(instance_number) > int(wanted_instance):
                logger.warning(f"{acs_session.tag}/{acs_device}: Killing session, instance overrun.")
                return None, None, hook_state

            # Rescan
            hook_state["pending_cwmp_id"] = "configure_xmpp_get"
            root, body = _cwmp_GetParameterNames_soap(
                f"{key}{instance_number}.", "configure_xmpp_get", acs_session
            )
            return root, body, hook_state

    # Get config from related device.
    device_config = get_device_config_dict(acs_device)
    # Get the config template
    yaml_struct = load_from_yaml(acs_device, "xmpp_template", config_version=device_config.get("django_acs.acs_config_name"))

    # Generate the final config_dict, by merging the yaml_struct template with the device_config
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
            addobject_list[0][0], "1977-01-20 00:00:00+00", response_cwmp_id, acs_session
        )
        return root, body, hook_state

    # Set the parameters
    logger.info(f"{acs_session.tag}/{acs_device}: Configuring XMPP")
    cwmp_id = uuid.uuid4().hex

    # Set the praramterkey, if there is no desired_config_level, use a placeholder value of "xmpp_done".
    if acs_device.current_config_level is None:
        parameter_key = str(settings.CWMP_CONFIG_INCOMPLETE_PARAMETERKEY_DATE)
    else:
        # If there is a current config level, we reuse it.
        parameter_key = str(acs_device.current_config_level)

    root, body = _cwmp_SetParameterValues_soap(
        config_dict, parameter_key, cwmp_id, acs_session
    )

    hook_state["hook_done"] = str(timezone.now())
    return root, body, hook_state


def track_parameters(acs_http_request, hook_state):
    acs_session = acs_http_request.acs_session
    acs_device = acs_session.acs_device

    if "no_track" in acs_device.hook_state.keys():
        hook_state["hook_done"] = str(timezone.now())
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
            # alright, update the ACS device with the new information.
            acs_device.acs_parameters = etree.tostring(
                root, xml_declaration=True
            ).decode("utf-8", "ignore")
            acs_device.acs_parameters_time = timezone.now()

            hook_state["hook_done"] = True
            return None, None, hook_state

    if "tracked_parameters" not in hook_state.keys():
        tracked_parameters = load_tracked_parameters(acs_device, config_version=get_device_config_dict(acs_device).get("django_acs.acs_config_name"))
        cwmp_id = uuid.uuid4().hex
        # logger.info(f'{acs_session.tag}: tracked_parameters: "{tracked_parameters}"')
        hook_state["tracked_parameters"] = tracked_parameters
        hook_state["pending_cwmp_id"] = cwmp_id
        root, body = cwmp_GetPrameterValues_soap(
            tracked_parameters, cwmp_id, acs_session
        )
        return root, body, hook_state

    return None, None, hook_state


def get_cpe_rpc_methods(acs_http_request, hook_state):
    acs_session = acs_http_request.acs_session

    if "hook_done" in hook_state.keys():
        return None, None, hook_state

    hook_state["hook_done"] = str(timezone.now())
    root, body = cwmp_GetRPCMethods(acs_session)
    return root, body, hook_state


def device_attributes(acs_http_request, hook_state):
    acs_session = acs_http_request.acs_session
    acs_device = acs_session.acs_device

    if "no_config" in acs_device.hook_state.keys():
        hook_state["hook_done"] = True
        return None, None, hook_state

    if acs_device.current_config_level == acs_device.desired_config_level:
        logger.debug(
            f"{acs_session.tag}/{acs_device}: current_config_level == desired_config_level, not doing attribute config."
        )
        hook_state["hook_done"] = str(timezone.now())
        return None, None, hook_state

    device_attributes_dict = load_notify_parameters(acs_device, config_version=get_device_config_dict(acs_device).get("django_acs.acs_config_name"))

    if not device_attributes_dict:
        logger.debug(f"{acs_session.tag}/{acs_device}: No atributes to configure.")
        hook_state["hook_done"] = True
        return None, None, hook_state

    # def cwmp_SetParameterAttributes(attribute_dict, ParameterKey, cwmp_id, acs_session):
    root, body = cwmp_SetParameterAttributes(
        device_attributes_dict,
        str(acs_device.current_config_level),
        "set:attributes",
        acs_session,
    )
    hook_state["hook_done"] = True

    return root, body, hook_state


def device_config(acs_http_request, hook_state):
    acs_session = acs_http_request.acs_session
    acs_device = acs_session.acs_device

    # If the device model has no device_config (), we are done...
    device_config = get_device_config_dict(acs_device)
    config_template = load_from_yaml(acs_device, "config_template", config_version=device_config.get("django_acs.acs_config_name"))

    if not config_template:
        logger.debug(
            f"{acs_session.tag}/{acs_device}: device_config, device has no device_config template, hook is done."
        )
        hook_state["hook_done"] = str(timezone.now())
        return None, None, hook_state

    if "no_config" in acs_device.hook_state.keys():
        hook_state["hook_done"] = True
        return None, None, hook_state

    if not acs_session.client_ip_verified:
        logger.info(
            f"{acs_session.tag}/{acs_device}: Not configuring, client IP is not verified."
        )
        hook_state["hook_done"] = str(timezone.now())
        return None, None, hook_state

    if acs_device.current_config_level == acs_device.desired_config_level:
        logger.debug(
            f"{acs_session.tag}/{acs_device}: current_config_level == desired_config_level, not doing config."
        )
        hook_state["hook_done"] = str(timezone.now())
        return None, None, hook_state

    # Get the real associated device if any.
    related_device = acs_device.get_related_device()

    if not related_device:
        logger.info(
            f"{acs_session.tag}: {acs_device} has no related related_device not configuring."
        )
        hook_state["hook_done"] = str(timezone.now())
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
            logger.info(f"{acs_session.tag}/{acs_device}: Added instance:{key}{instance_number}, calling GetParameterNames")
            if int(instance_number) > int(wanted_instance):
                logger.warning(f"{acs_session.tag}/{acs_device}: Killing session, instance overrun.")
                return None, None, hook_state

            # Rescan
            response_cwmp_id = uuid.uuid4().hex
            hook_state["pending_cwmp_id"] = response_cwmp_id
            root, body = _cwmp_GetParameterNames_soap(
                f"{key}{instance_number}.", response_cwmp_id, acs_session
            )
            return root, body, hook_state

    # GetParameterNames, get the entire tree.
    if "getnames_sent" not in hook_state.keys():
        hook_state["getnames_sent"] = str(timezone.now())
        # Initiliaze&FLush the discovered_param_names dict.
        hook_state["discovered_param_names"] = {}

        response_cwmp_id = uuid.uuid4().hex
        hook_state["pending_cwmp_id"] = response_cwmp_id
        root, body = _cwmp_GetParameterNames_soap("", response_cwmp_id, acs_session)

        return root, body, hook_state

    # Get config from related device.
    device_config = get_device_config_dict(acs_device)
    # Get the confi template
    yaml_struct = load_from_yaml(acs_device, "config_template", config_version=device_config.get("django_acs.acs_config_name"))

    # Generate the final config_dict, by merging the yaml_struct template with the device_config
    config_dict = merge_config_template_dict(yaml_struct, device_config)

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
            addobject_list[0][0], "1977-01-20 00:00:00+00", response_cwmp_id, acs_session
        )
        return root, body, hook_state

    # Set the parameters
    cwmp_id = uuid.uuid4().hex
    parameter_key = str(acs_device.get_desired_config_level())
    root, body = _cwmp_SetParameterValues_soap(
        config_dict, parameter_key, cwmp_id, acs_session
    )

    acs_device.current_config_level = acs_device.get_desired_config_level()
    hook_state["hook_done"] = str(timezone.now())
    return root, body, hook_state


def preconfig(acs_http_request, hook_state):
    # Preconfig is given to all ACS devices that have a physical device. Regardless of IP address validation.
    # Preconfig is dumb, it does not attempt to do AddObjects for missing items.
    # Preconfig does not modify the parameter_key, it is preserved as is.
    acs_session = acs_http_request.acs_session
    acs_device = acs_session.acs_device

    # Load config template, and device specific config
    device_config = get_device_config_dict(acs_device)
    config_template = load_from_yaml(acs_device, "preconfig_template", config_version=device_config.get("django_acs.acs_config_name"))

    # If we do not have eventcode BOOTSTRAP, remove config that is only supposed to be applied at 0 BOOTSTRAP
    if "0 BOOTSTRAP" not in acs_session.inform_eventcodes:
        config_template = {k: v for k, v in config_template.items() if v.get("bootstrap_only", False) is False}

    # Generate the final config_dict, by merging the yaml_struct template with the device_config
    config_dict = merge_config_template_dict(config_template, device_config)

    # If we don't have any config to apply, we are done.
    if not config_dict:
        logger.debug(
            f"{acs_session.tag}/{acs_device}: pre_config empty, hook is done."
        )
        hook_state["hook_done"] = str(timezone.now())
        return None, None, hook_state

    related_device = acs_device.get_related_device()
    device_hook_state = acs_device.hook_state.get("preconfig", {})

    if "no_preconfig" in acs_device.hook_state.keys():
        hook_state["hook_done"] = True
        return None, None, hook_state
    if acs_device.hook_state.get("beacon_extender", False):
        hook_state["hook_done"] = True
        return None, None, hook_state

    if not related_device:
        logger.warning(
            f"{acs_session.tag}/{acs_device}: Not applying preconfig, the device is not in our inventory."
        )
        hook_state["hook_done"] = str(timezone.now())
        return None, None, hook_state

    # We only do the SetParameterValues once, if we have already sent it
    if "set_done" in hook_state.keys():
        hook_state["hook_done"] = str(timezone.now())
        return None, None, hook_state

    # If the config_level already is up to date, we don't do anything.
    if ( 
        acs_device.desired_preconfig_level 
        and acs_device.desired_preconfig_level != parse_datetime(device_hook_state.get("preconfig_level", ""))
    ):
        logger.info(f"{acs_session.tag}/{acs_device}: preconfig_level != desired_preconfig_level, doing preconfig.")
        pass
    elif (
        acs_device.current_config_level
        and acs_device.current_config_level == acs_device.desired_config_level
    ):
        logger.debug(
            f"{acs_session.tag}/{acs_device}: current_config_level == desired_config_level, not doing preconfig."
        )
        hook_state["hook_done"] = str(timezone.now())
        return None, None, hook_state

    logger.info(
        f"{acs_session.tag}/{acs_device}: Applying preconfig found related device {acs_device.get_related_device()}"
    )

    # Get config from related device.
    device_config = get_device_config_dict(acs_device)

    # Get the config template
    yaml_struct = load_from_yaml(acs_device, "preconfig_template", config_version=device_config.get("django_acs.acs_config_name"))

    # Generate the final config_dict, by merging the yaml_struct template with the device_config
    config_dict = merge_config_template_dict(yaml_struct, device_config)

    # Set the parameters
    cwmp_id = uuid.uuid4().hex
    parameter_key = str(acs_device.current_config_level)
    root, body = _cwmp_SetParameterValues_soap(
        config_dict, parameter_key, cwmp_id, acs_session
    )
    hook_state["pending_cwmp_id"] = cwmp_id
    hook_state["set_done"] = str(timezone.now())

    device_hook_state["preconfig_level"] = str(acs_device.desired_preconfig_level)
    acs_device.hook_state["preconfig"] = device_hook_state
    acs_device.save()

    return root, body, hook_state


def full_parameters_request(acs_http_request, hook_state):
    acs_session = acs_http_request.acs_session
    acs_device = acs_session.acs_device

    if acs_device.full_parameters_request is not True:
        hook_state["hook_done"] = str(timezone.now())
        return None, None, hook_state

    # Initialize the data struct, if it does not exist.
    if "data" not in hook_state.keys():
        hook_state["data"] = {}

    # Process responses
    if (
        acs_http_request.cwmp_rpc_method == "GetParameterNamesResponse"
        and acs_http_request.cwmp_id == "full_parameters_request_names"
    ):
        for infostruct in acs_http_request.soap_body.findall('.//ParameterInfoStruct'):
            key = infostruct.find('Name').text
            writable = infostruct.find('Writable').text
            if key not in hook_state["data"].keys():
                hook_state["data"][key] = {}
            hook_state["data"][key]["writable"] = writable

    if (
        acs_http_request.cwmp_rpc_method == "GetParameterValuesResponse"
        and acs_http_request.cwmp_id == "full_parameters_request_values"
    ):
        for valuestruct in acs_http_request.soap_body.findall('.//ParameterValueStruct'):
            key = valuestruct.find('Name').text
            value = valuestruct.find('Value').text
            type = valuestruct.find('Value').attrib['{%s}type' % acs_settings.SOAP_NAMESPACES['xsi']]
            if key not in hook_state["data"].keys():
                hook_state["data"][key] = {}
            hook_state["data"][key]["value"] = value
            hook_state["data"][key]["type"] = type

    if (
        acs_http_request.cwmp_rpc_method == "GetParameterAttributesResponse"
        and acs_http_request.cwmp_id == "full_parameters_request_attributes"
    ):
        for attributestruct in acs_http_request.soap_body.findall('.//ParameterAttributeStruct'):
            key = attributestruct.find('Name').text
            notification = attributestruct.find('Notification').text
            if key not in hook_state["data"].keys():
                hook_state["data"][key] = {}
            hook_state["data"][key]["notification"] = notification

    # Retreive Parameter Names,Attributes,Values
    root_object = acs_session.root_data_model.root_object

    if "get_names" not in hook_state.keys():
        root, body = _cwmp_GetParameterNames_soap(
            f"{root_object}.", "full_parameters_request_names", acs_session
        )
        hook_state["get_names"] = str(timezone.now())
        hook_state["pending_cwmp_id"] = "full_parameters_request_names"
        return root, body, hook_state

    if "get_values" not in hook_state.keys():
        root, body = cwmp_GetPrameterValues_soap(
            [f"{root_object}."], "full_parameters_request_values", acs_session
        )
        hook_state["get_values"] = str(timezone.now())
        hook_state["pending_cwmp_id"] = "full_parameters_request_values"
        return root, body, hook_state

    if "get_attributes" not in hook_state.keys():
        root, body = cwmp_GetPrameterAttributes_soap(
            [f"{root_object}."], "full_parameters_request_attributes", acs_session
        )
        hook_state["get_attributes"] = str(timezone.now())
        hook_state["pending_cwmp_id"] = "full_parameters_request_attributes"
        return root, body, hook_state

    # If we end up here we are done, do final processsing.
    parameter_count = len(hook_state["data"].keys())
    logger.info(f"{acs_session.tag}/{acs_device}: full_parameters_request collected {parameter_count} paramters.")
    acs_device.acs_full_parameters = hook_state["data"]
    acs_device.acs_full_parameters_time = str(timezone.now())
    acs_device.full_parameters_request = False
    acs_device.save()

    hook_state["data"] = {}

    return None, None, hook_state


def device_vendor_config(acs_http_request, hook_state):
    acs_session = acs_http_request.acs_session
    acs_device = acs_session.acs_device
    device_hook_state = acs_device.hook_state.get("device_vendor_config", {})

    if "hook_done" in hook_state.keys():
        return None, None, hook_state

    # Don't download vendor config files if thebeacon is an extender.
    if acs_device.hook_state.get("beacon_extender", False):
        hook_state["hook_done"] = str(timezone.now())
        return None, None, hook_state

    # Try to get the vendor config file. If there is no vendor config file, we are done.
    filename = acs_device.model.vendor_config_file
    if not filename:
        hook_state["hook_done"] = str(timezone.now())
        return None, None, hook_state

    # Get the latest download time.
    download_time = parse_datetime(
        device_hook_state.get("download_command_sent_at", "")
    )
    # Determine if we need to download the vendor config file.
    if download_time and "0 BOOTSTRAP" not in acs_session.inform_eventcodes:
        logger.debug(f"{acs_session.tag}/{acs_device}: Not downloading vendor config file (already downloaded).")
        hook_state["hook_done"] = str(timezone.now())
        return None, None, hook_state

    # NEW DOWNLOAD RESPONSE HERE ####
    cwmp_id = uuid.uuid4().hex

    software_url = acs_device.get_vendor_config_url(filename)

    root, body = cwmp_Download(software_url, cwmp_id, acs_session, filetype="3 Vendor Configuration File")
    logger.info(f"{acs_session.tag}/{acs_device}: Downloading vendor config file {filename}")
    hook_state["vendor_config_cwmp_id"] = cwmp_id
    device_hook_state["download_command_sent_at"] = str(timezone.now())
    hook_state["hook_done"] = str(timezone.datetime.now())
    acs_device.hook_state["device_vendor_config"] = device_hook_state
    acs_device.save()

    # return None, None, hook_state
    return root, body, hook_state


def device_firmware_upgrade(acs_http_request, hook_state):
    acs_session = acs_http_request.acs_session
    acs_device = acs_session.acs_device

    device_hook_state = acs_device.hook_state.get("device_firmware_upgrade", {})

    if "hook_done" in hook_state.keys():
        return None, None, hook_state

    if "download_ok" in hook_state.keys():
        return None, None, hook_state

    if "download_failed" in hook_state.keys():
        return None, None, hook_state

    if "download_cwmp_id" in hook_state.keys():
        # We have issued a download command, lets check if the response matches the cwmp id.
        if acs_http_request.cwmp_rpc_method == "DownloadResponse":
            logger.info(f"{acs_session}: Checking if DownloadResponse is ok.")
            rpc_response = acs_http_request.soap_body.find(
                "cwmp:%s" % acs_http_request.cwmp_rpc_method,
                acs_http_request.acs_session.soap_namespaces,
            )
            status = rpc_response.find("Status")
            if status is None:
                logger.warning(
                    f"{acs_session}: {acs_device} sent DownloadResponse without status code"
                )
            else:
                if status.text in ["0", "1"]:
                    logger.info(
                        f"{acs_session}: {acs_device} responded with status_code: {status.text} in DownloadResponse."
                    )
                    hook_state["download_ok"] = str(timezone.datetime.now())

                    # End the ACS session on OK DownloadResponse. We assume that the device will reconnect after the firmware update.
                    return "*END*", None, hook_state
                else:
                    logger.info(
                        f"{acs_session}: {acs_device} responded with status_code: {status.text} in DownloadResponse."
                    )
                    hook_state["download_failed"] = str(timezone.datetime.now())

            return None, None, hook_state

    if (
        acs_device.get_desired_software_version()
        and acs_device.current_software_version
        != acs_device.get_desired_software_version()
    ):

        # Don't download if the device just reported transfer complete.
        if "7 TRANSFER COMPLETE" in acs_session.inform_eventcodes:
            logger.info(
                f'{acs_session.tag}/{acs_device}: Suppessing firmware update, as this session has INFORM code "7 TRANSFER COMPLETE" '
            )
            hook_state["hook_done"] = str(timezone.now())
            return None, None, hook_state

        # Don't send more than one download command within 10 minutes.
        download_time = parse_datetime(
            device_hook_state.get("download_command_sent_at", "")
        )
        if (
            download_time
            and download_time + timezone.timedelta(minutes=10) > timezone.now()
        ):
            logger.info(
                f"{acs_session.tag}/{acs_device}: device_firmware_upgrade is in 10 minutes holdoff period."
            )
            hook_state["hook_done"] = str(timezone.now())
            return None, None, hook_state

        # If we need a different software we upgrade the device.
        logger.info(
            f"{acs_session.tag}/{acs_device}: Updating firmware {acs_device.current_software_version} -> {acs_device.get_desired_software_version()}"
        )

        # NEW DOWNLOAD RESPONSE HERE #
        cwmp_id = uuid.uuid4().hex

        software_url = acs_device.get_software_url(
            version=acs_device.get_desired_software_version()
        )

        root, body = cwmp_Download(software_url, cwmp_id, acs_session)
        hook_state["download_cwmp_id"] = cwmp_id
        device_hook_state["download_command_sent_at"] = str(timezone.now())
        acs_device.hook_state["device_firmware_upgrade"] = device_hook_state
        acs_device.save()
        return root, body, hook_state

    # If we end here, the firmware version is OK
    logger.debug(
        f"{acs_session}: Not updating firmware on {acs_device}, as it is the correct version."
    )
    hook_state["hook_done"] = str(timezone.datetime.now())
    return None, None, hook_state


def verify_client_ip(acs_http_request, hook_state):
    acs_session = acs_http_request.acs_session
    acs_device = acs_session.acs_device
    related_device = acs_device.get_related_device()

    if not related_device:
        logger.info(
            f"{acs_session}: Skip verify client IP, as there is not related device for {acs_device}."
        )
        return None, None, hook_state

    if "hook_done" in hook_state.keys():
        # If the client IP is already verified do nothing.
        return None, None, hook_state

    if acs_session.access_domain == "wifi":
        pass
    elif acs_session.access_domain == "mobile":
        logger.info(f"{acs_session}/{acs_device}: Mobile, use ICCID ({acs_device.hook_state.get('iccid', None)}) for validation.")

        acs_session.client_ip_verified = acs_device.get_related_device().verify_acs_client_ip(
            acs_session.client_ip, iccid=acs_device.hook_state.get('iccid', None)
        )

    elif acs_session.access_domain == "mobile_cpe":
        # We need to verify via the client IP but towards SIM ip's only, let MRX know by specifying mobile_ip=True
        # This also makes MRX associate the device to the relevant circuitdeviceport.
        connection_request_hostname = urlparse(acs_device.acs_connectionrequest_url).hostname

        if connection_request_hostname == acs_session.client_ip:
            logger.info(f"{acs_session}/{acs_device}: Is a candidate for router registration")
            register_router = True
        else:
            logger.info(f"{acs_session}/{acs_device}: Is NOT a candidate for router reg., client_ip:{acs_session.client_ip} != connection_request_hostname:{connection_request_hostname}")
            register_router = False

        logger.info(f"{acs_session}/{acs_device}: Mobile CPE, use SIM IP for verification (ip: {acs_session.client_ip})")
        acs_session.client_ip_verified = acs_device.get_related_device().verify_acs_client_ip(
            acs_session.client_ip, mobile_ip=True, register_router=register_router
        )
    else:
        # set acs_session.client_ip_verified based on the outcome of verify_acs_client_ip(acs_session.client_ip)
        acs_session.client_ip_verified = acs_session.acs_device.get_related_device().verify_acs_client_ip(
            acs_session.client_ip
        )
        
    logger.info(
        f"{acs_session}: client_ip_verified set to {acs_session.client_ip_verified} for client (ip: {acs_session.client_ip})"
    )

    acs_session.save()

    hook_state["hook_done"] = str(timezone.datetime.now())
    return None, None, hook_state


def beacon_extender_test(acs_http_request, hook_state):
    acs_session = acs_http_request.acs_session
    acs_device = acs_session.acs_device
    root_object = acs_device.hook_state["root_object"]

    # Only run test on Beacon 2
    if acs_device.model.name not in ["Beacon 2"]:
        hook_state["hook_done"] = str(timezone.now())
        return None, None, hook_state

    # Reset hook supression flags on boot
    if "1 BOOT" in acs_session.inform_eventcodes:
        logger.info(
            f"{acs_session.tag}/{acs_device}: beacon_extender_test clearing all data as boot is detected."
        )
        acs_device.hook_state.pop("no_preconfig", None)
        acs_device.hook_state.pop("no_config", None)
        acs_device.hook_state.pop("no_track", None)
        acs_device.hook_state.pop("beacon_extender", None)

    # If beacon_extender is alredy defined, skip the test.
    if "beacon_extender" in acs_device.hook_state.keys():
        hook_state["hook_done"] = str(timezone.now())
        return None, None, hook_state

    # PROCESS RESPONSE #
    if acs_http_request.cwmp_id == "beacon_extender_test:getnames":

        if acs_http_request.cwmp_rpc_method == "GetParameterValuesResponse":
            logger.info(
                f"{acs_session.tag}/{acs_device}: beacon_extender_test processing GetParameterValuesResponse/Fault."
            )

            value_dict = {}
            for valuestruct in acs_http_request.soap_body.findall('.//ParameterValueStruct'):
                key = valuestruct.find('Name').text
                value = valuestruct.find('Value').text
                value_dict[key] = value

            if value_dict.get(f"{root_object}.X_ALU-COM_Wifi.WorkMode", None) == "AP_Bridge":
                # The beacon is an extender.
                logger.info(
                    f"{acs_session.tag}/{acs_device}: beacon is an extender."
                )
                acs_device.hook_state["no_preconfig"] = True
                acs_device.hook_state["no_config"] = True
                acs_device.hook_state["no_track"] = True
                acs_device.hook_state["beacon_extender"] = True
            elif value_dict.get(f"{root_object}.X_ALU-COM_Wifi.WorkMode", None) == "RGW":
                logger.info(
                    f"{acs_session.tag}/{acs_device}: beacon is a router."
                )
                acs_device.hook_state["beacon_extender"] = False
            else:
                logger.warning(
                    f"{acs_session.tag}/{acs_device}: could not determine beacon router/extender status."
                )

        acs_device.save()
        hook_state["hook_done"] = True
        return None, None, hook_state

    if "getnames_sent" not in hook_state.keys():
        hook_state["getnames_sent"] = str(timezone.now())
        response_cwmp_id = "beacon_extender_test:getnames"
        hook_state["pending_cwmp_id"] = response_cwmp_id
        root, body = cwmp_GetPrameterValues_soap(
            [f"{root_object}.X_ALU-COM_Wifi.WorkMode"],
            response_cwmp_id,
            acs_session
        )

        return root, body, hook_state

    # Catchall, should not be reached.
    return None, None, hook_state


def factory_default(acs_http_request, hook_state):
    acs_session = acs_http_request.acs_session
    acs_device = acs_session.acs_device

    if acs_device.factory_default_request is False:
        hook_state["hook_done"] = str(timezone.now())
        return None, None, hook_state

    # Process response
    if acs_http_request.cwmp_rpc_method == "FactoryResetResponse":
        if acs_http_request.cwmp_id == "factory_default":
            acs_device.factory_default_request = False
            acs_device.save()
            return "*END*", None, hook_state

    # If the current session has eventcode "0 BOOTSTRAP", we ignore the pending FactoryReset.
    if "0 BOOTSTRAP" in acs_session.inform_eventcodes:
        logger.info(f"{acs_session.tag}/{acs_device}: Ignoring pending FactoryReset, device reported \"0 BOOTSTRAP\" in current session.")
        acs_device.factory_default_request = False
        acs_device.save()
        hook_state["hook_done"] = str(timezone.now())
        return None, None, hook_state

    # Issue the factory default command.
    root, body = cwmp_FactoryReset_soap("factory_default", acs_session)
    return root, body, hook_state


def avm_access(acs_http_request, hook_state):
    acs_session = acs_http_request.acs_session
    acs_device = acs_session.acs_device
    root_object = acs_session.root_data_model.root_object

    # Only run on AVM products.
    if acs_device.model.name not in ["FRITZ!Box", "FRITZ!Repeater"]:
        hook_state["hook_done"] = str(timezone.now())
        return None, None, hook_state

    # Get overview of exsisting users.
    if not hook_state.get("users_retreived"):
        hook_state["users_retreived"] = str(timezone.now())
        root, body = cwmp_GetPrameterValues_soap([f"{root_object}.User."], "avm:user_retreive", acs_session)
        return root, body, hook_state

    # Process  avm:user_retreive response.
    if acs_http_request.cwmp_id == "avm:user_retreive":
        if acs_http_request.cwmp_rpc_method == "GetParameterValuesResponse":
            logger.info(
                f"{acs_session.tag}/{acs_device}: beacon_extender_test processing GetParameterValuesResponse/Fault."
            )

            value_dict = {}
            for valuestruct in acs_http_request.soap_body.findall('.//ParameterValueStruct'):
                key = valuestruct.find('Name').text
                value = valuestruct.find('Value').text
                value_dict[key] = value

            print(value_dict)

    # Set user_config
    if not hook_state.get("user_set"):
        hook_state["user_set"] = str(timezone.now())

        parameter_dict = {
            "InternetGatewayDevice.UserInterface.RemoteAccess.Enable": ("boolean", True),
            "InternetGatewayDevice.UserInterface.RemoteAccess.Port": ("unsignedInt", 14426),
            "InternetGatewayDevice.User.1.Enable": ("boolean", True),
            "InternetGatewayDevice.User.1.Username": ("string", "remoto"),
            "InternetGatewayDevice.User.1.Password": ("string", "RemotoMan1"),
            "InternetGatewayDevice.User.1.RemoteAccessCapable": ("boolean", True),
        }

        # def cwmp_SetParameterAttributes(attribute_dict, ParameterKey, cwmp_id, acs_session):
        root, body = _cwmp_SetParameterValues_soap(
            parameter_dict,
            str(acs_device.current_config_level),
            "set:attributes",
            acs_session,
        )

        return root, body, hook_state

    hook_state["hook_done"] = str(timezone.now())
    logger.info(f"{acs_session.tag}/{acs_device}: Hook called.")

    # Send None, no action.
    return None, None, hook_state


def iccid_query(acs_http_request, hook_state):
    acs_session = acs_http_request.acs_session
    acs_device = acs_session.acs_device
    root_object = acs_session.root_data_model.root_object

    # Process  iccid_retrieve response.
    if acs_http_request.cwmp_id == "iccid_retrieve":
        if acs_http_request.cwmp_rpc_method == "GetParameterValuesResponse":
            logger.info(
                f"{acs_session.tag}/{acs_device}: iccid_retrieve processing GetParameterValuesResponse/Fault."
            )

            value_dict = {}
            for valuestruct in acs_http_request.soap_body.findall('.//ParameterValueStruct'):
                key = valuestruct.find('Name').text
                value = valuestruct.find('Value').text
                value_dict[key] = value
            acs_device.hook_state["iccid"] = value_dict.get(f"{root_object}.Cellular.Interface.1.USIM.ICCID", None)

    # Get the ICCID
    if not hook_state.get("iccid_retreived"):
        hook_state["iccid_retreived"] = str(timezone.now())
        root, body = cwmp_GetPrameterValues_soap([f"{root_object}.Cellular.Interface.1.USIM.ICCID"], "iccid_retrieve", acs_session)
        return root, body, hook_state

    # We are done
    hook_state["hook_done"] = str(timezone.now())
    return None, None, hook_state


# HOOK HELPER FUNCTIONS


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
    elif value_type == "hexBinary":
        valueobj.set(nse("xsi", "type"), "xsd:hexBinary")
        valueobj.text = str(value)

    return element


def _add_pas(element, key, value):
    struct = etree.SubElement(element, "ParameterAttributesStruct")
    nameobj = etree.SubElement(struct, "Name")
    nameobj.text = key
    notificationchangeobj = etree.SubElement(struct, "NotificationChange")
    notificationchangeobj.text = "true"
    notificationobj = etree.SubElement(struct, "Notification")
    notificationobj.text = str(value)
    accesslistchangeobj = etree.SubElement(struct, "AccessListChange")
    accesslistchangeobj.text = "0"
    accesslistobj = etree.SubElement(struct, "AccessList")
    accesslistobj.set(nse("soap-enc", "arrayType"), "cwmp:ParameterValueStruct[%s]" % 0)


def _cwmp_SetParameterValues_soap(config_dict, ParameterKey, cwmp_id, acs_session):
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


def cwmp_SetParameterAttributes(attribute_dict, ParameterKey, cwmp_id, acs_session):
    cwmp_obj = etree.Element(nse("cwmp", "SetParameterAttributes"))
    paramlist = etree.SubElement(cwmp_obj, "SetParameterAttributesStruct")

    for param_key, param_value in attribute_dict.items():
        _add_pas(paramlist, param_key, param_value)

    paramlist.set(
        nse("soap-enc", "arrayType"),
        "cwmp:SetParameterAttributesStruct[%s]" % len(paramlist),
    )
    paramkey = etree.SubElement(cwmp_obj, "ParameterKey")
    paramkey.text = ParameterKey

    root, body = get_soap_envelope(cwmp_id, acs_session)
    body.append(cwmp_obj)

    return root, body


def _cwmp_GetParameterNames_soap(key, cwmp_id, acs_session, next_level=0):
    cwmp_obj = etree.Element(nse("cwmp", "GetParameterNames"))
    # add the inner response elements, but without XML namespace (according to cwmp spec!)

    parampath = etree.SubElement(cwmp_obj, "ParameterPath")
    parampath.text = key
    nextlevel = etree.SubElement(cwmp_obj, "NextLevel")
    nextlevel.text = str(next_level)

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


def cwmp_GetPrameterValues_soap(key_list, cwmp_id, acs_session):
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


def cwmp_GetPrameterAttributes_soap(key_list, cwmp_id, acs_session):
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

    cwmp_obj = etree.Element(nse("cwmp", "GetParameterAttributes"))
    paramlist = etree.SubElement(cwmp_obj, "ParameterNames")

    for key in get_list:
        nameobj = etree.SubElement(paramlist, "string")
        nameobj.text = key

    paramlist.set(nse("soap-enc", "arrayType"), "xsd:string[%s]" % len(paramlist))
    root, body = get_soap_envelope(cwmp_id, acs_session)
    body.append(cwmp_obj)

    return root, body


def cwmp_FactoryReset_soap(cwmp_id, acs_session):
    cwmp_obj = etree.Element(nse("cwmp", "FactoryReset"))
    root, body = get_soap_envelope(cwmp_id, acs_session)
    body.append(cwmp_obj)

    return root, body


def cwmp_GetRPCMethods(acs_session):
    cwmp_obj = etree.Element(nse("cwmp", "GetRPCMethods"))
    root, body = get_soap_envelope("GetRPCMethodsId", acs_session)
    body.append(cwmp_obj)

    return root, body


def cwmp_Download(firmware_url, cwmp_id, acs_session, filetype="1 Firmware Upgrade Image", filesize=None):
    cwmp_obj = etree.Element(nse("cwmp", "Download"))
    root, body = get_soap_envelope(cwmp_id, acs_session)

    commandkey = etree.SubElement(cwmp_obj, "CommandKey")
    commandkey.text = "cwmp_Download"
    filetype_element = etree.SubElement(cwmp_obj, "FileType")
    filetype_element.text = filetype
    if filesize:
        filesize_element = etree.SubElement(cwmp_obj, "FileSize")
        filesize_element.text = str(filesize)
    url = etree.SubElement(cwmp_obj, "URL")
    url.text = firmware_url

    body.append(cwmp_obj)
    return root, body


def get_addobject_list(config_dict, parameternames_dict):
    # Generate a set of Addobject calls if needed.
    addobject_set = set()

    parameternames_keys = list(parameternames_dict)

    missing_keys = set()

    # Iterate over each config_dict item at test if it exists
    # Skip config_keys that exist as exact matches.
    for config_key in config_dict.keys():
        if config_key not in parameternames_keys:
            missing_keys.add(config_key)

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
                [key.startswith(shortened_config_key) for key in parameternames_keys if key]
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


def get_device_config_dict(acs_device):
    related_device = acs_device.get_related_device()
    # Retreives the device device_config dict.
    device_config = {}
    if related_device:
        device_config = related_device.get_acs_config(access_domain=acs_device.hook_state.get("latest_access_domain", None))

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

    return device_config


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
        # logger.info(f"Merging {template_key}")
        if "type" not in template_values_dict.keys():
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


def load_notify_parameters(acs_device, config_version="default"):
    # Load the YAML config, and get it as a list of dicts.
    track_dict = load_from_yaml(acs_device, "tracked_parameters", config_version)

    # Build a set for paths that should have notifications.
    device_notify_dict = {}

    for k, v in track_dict.items():
        if v.get('notify', None) is None:
            continue

        if v.get('leaf', True) is True:
            device_notify_dict[k] = v.get('notify')
        else:
            device_notify_dict[f"{k}."] = v.get('notify')

    return device_notify_dict


def load_tracked_parameters(acs_device, config_version="default"):
    # Load the YAML config, and get it as a list of dicts.
    track_dict = load_from_yaml(acs_device, "tracked_parameters", config_version)

    # Build a set for paths that should be tracked. 
    device_tracked_set = set()

    # Iterate over items, and determine if it is a leaf or not. 
    for k, v in track_dict.items():
        if v.get('leaf', True) is True:
            device_tracked_set.add(k)
        else:
            device_tracked_set.add(f"{k}.")
    
    return sorted(list(device_tracked_set))


def load_from_yaml(acs_device, field_name, config_version="default"):
    # Load the YAML template from the requested AcsDeviceModel field, it contains all config versions.
    acs_model = acs_device.model
    yaml_struct = yaml.safe_load(getattr(acs_model, field_name))

    # If we did not load anything from the AcsDeviceModel config field, we return an empty dict.
    if yaml_struct is None:
        return {}

    # Get the root object for the current AcsDevice, this should alway be defined from the Inform processing.
    root_object = acs_device.hook_state["root_object"]

    # Search for available config version until one is available with descending prefernece, version+root_object, version, default.
    if f"{config_version}_{root_object}" in yaml_struct.keys():
        logger.debug(f"Loading YAML for {acs_device}, field_name:{field_name}, config_version: {config_version}")
        config_version = f"{config_version}_{root_object}"
    elif config_version in yaml_struct.keys():
        logger.debug(f"Loading YAML for {acs_device}, field_name:{field_name}, config_version: {config_version}")
        pass
    else:
        config_version = "default"
        logger.debug(f"Loading YAML for {acs_device}, field_name:{field_name}, config_version: {config_version}")

    # Flatten the data.
    flattened_yaml_struct = flatten_yaml_struct(yaml_struct[config_version])

    return flattened_yaml_struct


def flatten_yaml_struct(yaml_struct, key_path="", out_data=None):
    if out_data is None:
        out_data = {}
    for k, v in yaml_struct.items():
        if isinstance(v, dict):
            new_key_path = ".".join([str(i) for i in [key_path, k] if i])
            flatten_yaml_struct(v, new_key_path, out_data)
        else:
            if key_path not in out_data.keys():
                out_data[key_path] = {k: v}
            else:
                out_data[key_path][k] = v
    return out_data
