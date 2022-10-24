

# External deps
import json, logging, uuid
from lxml import etree
from ipware.ip import get_ip
from defusedxml.lxml import fromstring

# Dajngo deps
from django.utils import timezone
from django.utils.dateparse import parse_datetime

# Django model deps
from django.db.models import F
from .models import *

from .utils import get_value_from_parameterlist, create_xml_document
from .response import nse, get_soap_envelope
from .conf import acs_settings

logger = logging.getLogger('django_acs.%s' % __name__)


mock_data = '''
# Baseconfig
InternetGatewayDevice.ManagementServer.PeriodicInformInterval | unsignedInt | django_acs.acs.informinterval | 60

# Xmpp
InternetGatewayDevice.XMPP.Connection.1.Domain | string | django_acs.acs.xmpp_connection_domain
InternetGatewayDevice.XMPP.Connection.1.Enable | boolean | django_acs.acs.xmpp_connection_enable
InternetGatewayDevice.XMPP.Connection.1.Password | string | django_acs.acs.xmpp_connection_password
InternetGatewayDevice.XMPP.Connection.1.Username | string | django_acs.acs.xmpp_connection_username
InternetGatewayDevice.XMPP.Connection.1.UseTLS | boolean | django_acs.acs.xmpp_connection_usetls
InternetGatewayDevice.XMPP.Connection.1.Resource | string | django_acs.acs.xmpp_server
InternetGatewayDevice.XMPP.Connection.1.X_ALU_COM_XMPP_Port | int |django_acs.acs.xmpp_server_port

# Management vlan
InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.X_D0542D_ServiceList | string | django_acs.management.ip.servicelist
InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.X_ALU-COM_WanAccessCfg.HttpsDisabled | boolean | django_acs.management.ip.https_disabled

# Internet vlan
InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANEthernetLinkConfig.X_ALU-COM_VLANIDMark | int | django_acs.internet.vlan.id
InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANEthernetLinkConfig.X_ALU-COM_Mode | unsignedInt | django_acs.internet.vlan.mode

# Internet IP interface
InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANIPConnection.1.ConnectionType | string | django_acs.internet.ip.type
InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANIPConnection.1.Enable | boolean | django_acs.internet.ip.enable
InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANIPConnection.1.X_D0542D_ServiceList | string | django_acs.internet.ip.servicelist

# 2.4GHz WIFI

InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.Enable | boolean | django_acs.wifi.n_enable
InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.Channel | unsignedInt | django_acs.wifi.bg_channel
InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID | string | django_acs.wifi.bg_ssid
InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1.KeyPassphrase | string | django_acs.wifi.n_wpapsk

# 5 Ghz WIFI

InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.Enable | boolean | django_acs.wifi.bg_enable
InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.Channel | unsignedInt | django_acs.wifi.n_channel
InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.SSID | string | django_acs.wifi.n_ssid
InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.PreSharedKey.1.KeyPassphrase | string | django_acs.wifi.bg_wpapsk
'''



def _process_inform(acs_http_request,hook_state):
    acs_session = acs_http_request.acs_session
    acs_device = acs_session.acs_device

    # Check the hook_state
    if acs_http_request.cwmp_rpc_method == 'Inform' and 'inform_received' in hook_state.keys():
        # If we receive a second Inform in the same session, signal this as an error.
        logger.info(f"{acs_session}: We have received an inform already in this sesson")
        hook_state['inform_multiple_error'] = str(timezone.now())
        return False,None,hook_state

    elif 'inform_done' in hook_state.keys():
        # The inform is done.
        # Do nothing.
        return None,None,hook_state

    elif 'inform_received' in hook_state.keys() and acs_http_request.soap_body is False:
        # This is the empty post that indicates that the inform phase is done.
        # Do nothing, and mark the inform as done.
        hook_state['inform_done'] = str(timezone.now())
        return None,None,hook_state

    elif acs_http_request.cwmp_rpc_method == 'TransferComplete':
        logger.info(f"{acs_session}: {acs_device} sent a TransferComplete message.")

        # Inform processed OK, prepare a response
        root, body = get_soap_envelope(acs_http_request.cwmp_id, acs_session)
        cwmp = etree.SubElement(body, nse('cwmp', 'TransferCompleteResponse'))
        ### add the inner response elements, without namespace (according to cwmp spec!)
        maxenv = etree.SubElement(cwmp, 'MaxEnvelopes')
        maxenv.text = '1'
        hook_state['transfer_complete'] = str(timezone.now())
        return root,body,hook_state

    elif acs_http_request.cwmp_rpc_method != 'Inform':
        # If we receive anything that is not an inform, throw an error.
        logger.info(f"{acs_session}: The session must begin with an inform. Request {acs_http_request} is not an inform.")
        return False,None,hook_state


    # If we make to here, we process the inform.
    # A session has to begin with an inform, so if we get anything else we throw an error.

    # get Inform xml element
    inform = acs_http_request.soap_body.find('cwmp:Inform', acs_session.soap_namespaces)

    ### determine which data model version this device is using
    datamodel, created = CwmpDataModel.objects.get_or_create(
        name=acs_http_request.acs_session.determine_data_model(inform)
    )
    logger.info(f"{acs_session}: ACS client is using data model %s" % datamodel)
    acs_session.root_data_model = datamodel
    root_object = acs_session.root_data_model.root_object

    logger.info(f"ROOT OBJECT: {root_object}")

    deviceid = inform.find('DeviceId')
    mandatory_inform_fields = ['SerialNumber','Manufacturer','ProductClass','OUI']
    for inform_field in mandatory_inform_fields:
        field_value = deviceid.find(inform_field)
        print(f"Testing field {inform_field} it is \"{field_value.text}\"")
        if field_value is None or field_value.text == "":
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
        name__iexact = str(deviceid.find("ProductClass").text),
        defaults = {
            "name": str(deviceid.find("ProductClass").text),
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

    # Update acs_device data
    # get parameterlist from the Inform payload
    parameterlist = inform.find('ParameterList')

    ### update current_config_level from Device.ManagementServer.ParameterKey
    parameterkey = get_value_from_parameterlist(parameterlist, f"{root_object}.ManagementServer.ParameterKey")
    if not parameterkey:
        acs_device.current_config_level = None
    else:
        acs_device.current_config_level = parse_datetime(parameterkey)

    ### update latest_inform time
    acs_device.acs_latest_inform = timezone.now()

    ### update current_software_version
    acs_device.current_software_version = get_value_from_parameterlist(parameterlist, f"{root_object}.DeviceInfo.SoftwareVersion")

    logger.info(get_value_from_parameterlist(parameterlist, f"{root_object}.DeviceInfo.SoftwareVersion"))

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


    # Process inform ParamterList 

    # Inform processed OK, prepare a response
    root, body = get_soap_envelope(acs_http_request.cwmp_id, acs_session)
    cwmp = etree.SubElement(body, nse('cwmp', 'InformResponse'))
    ### add the inner response elements, without namespace (according to cwmp spec!)
    maxenv = etree.SubElement(cwmp, 'MaxEnvelopes')
    maxenv.text = '1'

    hook_state['inform_received'] = str(timezone.now())
    return root,body,hook_state


def _device_config(acs_http_request,hook_state):
    acs_session = acs_http_request.acs_session
    acs_device = acs_session.acs_device

    if 'hook_done' in hook_state.keys():
        print(f"_device_config alredy done")
        return None,None,hook_state

    if 'no_phy_device' in hook_state.keys():
        print(f"_device_config has no phy_device.")
        return None,None,hook_state

    # Get the real associated device if any.
    phy_device = acs_device.get_related_device()

    if not phy_device:
        hook_state["no_phy_device"] = True
        logger.info(f"{acs_session.tag}: {acs_device} has no related phy_device.")
        return None,None,hook_state

    # Process incoming GetParameterNamesResponse
    if acs_http_request.cwmp_rpc_method == "GetParameterNamesResponse":
        if acs_http_request.cwmp_id == hook_state["pending_cwmp_id"]:
            logger.info(f"{acs_session.tag}: Got response to process.")

            for param_info_struct in acs_http_request.soap_body.findall('.//ParameterInfoStruct'):
                key = param_info_struct.find('Name').text
                writeable = param_info_struct.find('Writable').text
                hook_state["discovered_param_names"][key] = writeable

    if acs_http_request.cwmp_rpc_method == "AddObjectResponse":
        if acs_http_request.cwmp_id == hook_state["addobject"]["pending_cwmp_id"]:
            key = hook_state["addobject"]["key"]
            wanted_instance = hook_state["addobject"]["wanted_index"]
            logger.info(f"{acs_session.tag}: Got AddObjectResponse to process.")

            instance_number = acs_http_request.soap_body.find('.//InstanceNumber').text
            print(f"Added instance:{key}{instance_number}, calling GetParameterNames")
            if int(instance_number) > int(wanted_instance):
                print("Killing session, instance overrun.")
                return None,None,hook_state

            # Rescan
            response_cwmp_id = uuid.uuid4().hex
            hook_state["pending_cwmp_id"] = response_cwmp_id
            root,body = _cwmp_GetParameterNames_soap(f"{key}{instance_number}.",response_cwmp_id,acs_session)
            return root,body,hook_state

    # GetParamterNames, get the entire tree.
    if not "getnames_sent" in hook_state.keys():
        hook_state["getnames_sent"] = str(timezone.now())
        # Initiliaze&FLush the discovered_param_names dict.
        hook_state['discovered_param_names'] = {}

        response_cwmp_id = uuid.uuid4().hex
        hook_state["pending_cwmp_id"] = response_cwmp_id
        root,body = _cwmp_GetParameterNames_soap("",response_cwmp_id,acs_session)

        return root,body,hook_state

    # Test if we need to call Addobject
    #addobject_list = get_addobject_list(config_dict,parameternames_dict)



    # Generate the config
    template_dict = _parse_config_template(mock_data)
    config_dict = _merge_config_template(template_dict,phy_device.get_acs_config())

    get_list = _shorten_keylist(config_dict)


    # Test if we need to call Addobject
    addobject_list = get_addobject_list(config_dict,hook_state["discovered_param_names"])

    if addobject_list:
        logger.info(f"{acs_session}: Adding object {addobject_list[0][0]}")
        response_cwmp_id = uuid.uuid4().hex
        hook_state['addobject'] = {"pending_cwmp_id": response_cwmp_id, "key": addobject_list[0][0], "wanted_index": addobject_list[0][1]}
        root,body = _cwmp_AddObject_soap(addobject_list[0][0],"hejsa",response_cwmp_id,acs_session)
        return root,body,hook_state

    # Get the current config, in order to diff it against desired state. And test if we need to
    # do some Addobject calls first.
    #if not "get_list" in hook_state.keys():
    #    hook_state['get_list'] = get_list
    #    hook_state['discovered_param_names'] = {}


#    if hook_state['get_list']:
#        print("#########################")
#        print("\n".join(hook_state["get_list"]))
#        print("#########################")
#        key = hook_state["get_list"].pop()
#        response_cwmp_id = uuid.uuid4().hex
#        hook_state["pending_cwmp_id"] = response_cwmp_id
#        root,body = _cwmp_GetParameterNames_soap(key,response_cwmp_id,acs_session)
#        return root,body,hook_state




#    if not 'get_sent' in hook_state.keys():
#        response_cwmp_id = uuid.uuid4().hex
#        root,body = _cwmp_GetPrameterValues_soap(get_list,response_cwmp_id,acs_session)
#        hook_state['get_sent'] = True
#        print("###########################")
#        print(etree.tostring(root,pretty_print=True).decode('utf8'))
#        print("###########################")
#        return root,body,hook_state



    # Get the current state
    # Add if something is missing
    # Set the config
    # States
    # get_sent
    # get_done

    device_tracked_dict = {
        'InternetGatewayDevice.ManagementServer.': True,
        'InternetGatewayDevice.LANDevice.1.WLANConfiguration.2.': True,
    }
    device_config_dict = {
        'InternetGatewayDevice.ManagementServer.PeriodicInformInterval': ('unsignedInt','60',None),
    }

    # Create a list of unique non overlapping get paramters
    raw_get_list = list(device_tracked_dict.keys()) + list(device_config_dict.keys())
    raw_get_list = get_list


    cwmp_id = uuid.uuid4().hex
    paramter_key = "Hejsa"
    root,body = _cwmp_GetPrameterValues_soap(raw_get_list,parameter_key,cwmp_id,acs_session)
    root,body = _cwmp_SetParameterNames_soap(config_dict,paramter_key,cwmp_id,acs_session)

    hook_state['hook_done'] = str(timezone.now())
    return root,body,hook_state


def _preconfig(acs_http_request,hook_state):

    if "preconfig_sent" in hook_state.keys():
        #logger.info(f"Preconfig alredy sent")
        return None,None,hook_state

    '''Preconfig is given to all ACS devices that have a physical device. Regardless of IP address validation.'''
    acs_session = acs_http_request.acs_session
    acs_device = acs_session.acs_device
    related_device = acs_device.get_related_device()

    if acs_device.get_related_device():
        logger.info(f"{acs_session}: Applying preconfig to {acs_device} as it is related with {acs_device.get_related_device()}")
    else:
        logger.info(f"{acs_session}: Not applying preconfig to {acs_device} as it is not in our inventory.")

    # Model preconfig list
    # Format is list of tuple ('factory_default_only','active_tracked','paramter_name','type','static_value','acs_config_key')
    # If acs_config_key exists, it takes preference. The datatype in inferred.

    model_preconfig_dict = {
#         'Device.ManagementServer.PeriodicInformInterval': ('unsignedInt','180',None),
        'InternetGatewayDevice.ManagementServer.PeriodicInformInterval': ('unsignedInt','60',None),
        'InternetGatewayDevice.ManagementServer.AutoCreateInstances': ('boolean', False, None),
#        'InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID': ('string',None,'django_acs.wifi.bg_ssid'),
#        'Fantasy.43.Hejsa': ('string',None,'nixi-bixi')
    }
    
    if related_device:
        device_preconfig_dict = related_device.get_acs_config()
    else:
        device_preconfig_dict = {}
    cwmp_obj = etree.Element(nse('cwmp', 'SetParameterValues'))
    paramlist = etree.SubElement(cwmp_obj, 'ParameterList')

    for parameter_name,(paramter_type,static_value,dynamic_value_key) in model_preconfig_dict.items():
        if dynamic_value_key != None:
            if dynamic_value_key in device_preconfig_dict.keys():
                _add_pvs_type(paramlist,parameter_name,paramter_type,device_preconfig_dict[dynamic_value_key])
            elif static_value != None:
                _add_pvs_type(paramlist,parameter_name,paramter_type,static_value)
            else:
                continue
        else:
            if static_value != None:
                _add_pvs_type(paramlist,parameter_name,paramter_type,static_value)

    paramlist.set(nse('soap-enc', 'arrayType'), "cwmp:ParameterValueStruct[%s]" % len(paramlist))

    response_cwmp_id = uuid.uuid4().hex
    root, body = get_soap_envelope(response_cwmp_id,acs_session)
    body.append(cwmp_obj)

    paramkey = etree.SubElement(cwmp_obj, 'ParameterKey')
    paramkey.text = "2022-10-14 16:46:48.473230"

    hook_state['preconfig_sent'] = str(timezone.now())
    return root,body,hook_state


####### HOOK HELPER FUNCTIONS #######

def _add_pvs_type(element,key,value_type,value):
    struct = etree.SubElement(element, "ParameterValueStruct")
    nameobj = etree.SubElement(struct, "Name")
    nameobj.text = key
    valueobj = etree.SubElement(struct, 'Value')

    if value_type == "boolean":
        valueobj.set(nse('xsi', 'type'), "xsd:boolean")
        valueobj.text = str(value).lower()
    elif value_type == "unsignedInt":
        valueobj.set(nse('xsi', 'type'), "xsd:unsignedInt")
        valueobj.text = str(int(value))
    elif value_type == "string":
        valueobj.set(nse('xsi', 'type'), "xsd:string")
        valueobj.text = str(value)
    elif value_type == "int":
        valueobj.set(nse('xsi', 'type'), "xsd:int")
        valueobj.text = str(int(value))

    return element

def _cwmp_SetParameterNames_soap(config_dict,paramter_key,cwmp_id,acs_session):
    cwmp_obj = etree.Element(nse('cwmp', 'SetParameterValues'))
    paramlist = etree.SubElement(cwmp_obj, 'ParameterList')

    for param_key,(param_type,param_value) in config_dict.items():
        _add_pvs_type(paramlist,param_key,param_type,param_value)

    root, body = get_soap_envelope(cwmp_id,acs_session)
    body.append(cwmp_obj)

    paramlist.set(nse('soap-enc', 'arrayType'), "cwmp:ParameterValueStruct[%s]" % len(paramlist))
    return root,body


def _cwmp_GetParameterNames_soap(key,cwmp_id,acs_session,next_level=True):
    cwmp_obj = etree.Element(nse('cwmp', 'GetParameterNames'))
    ### add the inner response elements, but without XML namespace (according to cwmp spec!)
    
    parampath = etree.SubElement(cwmp_obj, 'ParameterPath')
    parampath.text = key
    nextlevel = etree.SubElement(cwmp_obj, 'NextLevel')
    nextlevel.text = "0"

    root, body = get_soap_envelope(cwmp_id,acs_session)
    body.append(cwmp_obj)

    return root,body


def _cwmp_AddObject_soap(key,ParameterKey,cwmp_id,acs_session):
    cwmp_obj = etree.Element(nse('cwmp', 'AddObject'))
    object_name = etree.SubElement(cwmp_obj,'ObjectName')
    object_name.text = key

    root, body = get_soap_envelope(cwmp_id,acs_session)
    body.append(cwmp_obj)

    paramkey = etree.SubElement(cwmp_obj, 'ParameterKey')
    paramkey.text = ParameterKey
    return root,body

def _cwmp_GetPrameterValues_soap(key_list,ParameterKey,cwmp_id,acs_session):
    # Create a list of unique paramters we want to get info for.
    get_list = []
    for new_key in sorted(key_list,key=len):
        found = False
        for inserted_key in get_list:
            if new_key.startswith(inserted_key):
                found = True
                break
        if not found:
            get_list.append(new_key)

    cwmp_obj = etree.Element(nse('cwmp', 'GetParameterValues'))
    paramlist = etree.SubElement(cwmp_obj, 'ParameterNames')

    for key in get_list:
        nameobj = etree.SubElement(paramlist, "string")
        nameobj.text = key
    
    paramlist.set(nse('soap-enc', 'arrayType'), "xsd:string[%s]" % len(paramlist))
    root, body = get_soap_envelope(cwmp_id,acs_session)
    body.append(cwmp_obj)
    paramkey = etree.SubElement(cwmp_obj, 'ParameterKey')
    paramkey.text = ParameterKey
    
    return root,body


def _parse_config_template(template):
    parsed_data = {}

    for line in template.splitlines():
        if line.startswith("#"): continue
        if line.isspace(): continue
        if line == "": continue
        line_fields = [f.strip() for f in line.split("|")]
        if len(line_fields) == 4:
            param, param_type, config_key, param_default = line_fields
        elif len(line_fields) == 3:
            param, param_type, config_key = line_fields
            param_default = None

        else:
            logger.info(f"Unable to parse line \"{line}\"")
            continue

        parsed_data[param] = (param_type,config_key,param_default)

    return parsed_data

def _merge_config_template(template_dict,config_dict):
    # Merge the template woth the config from get_acs_config()
    # Merging rules
    # 1. If neither default value or configdict has a value, the paramter is dropped.
    # 2. If the configdict has no value the default is used.

    output_dict = {}
    for param in template_dict.keys():
        param_type,config_key,param_default = template_dict[param]
#        print(f"Looking for {config_key} in config_dict")
        if config_key in config_dict.keys():
            output_dict[param] = (param_type,config_dict[config_key])
        elif param_default != None:
            output_dict[param] = (param_type,param_default)

    return output_dict

def _shorten_keylist(key_list,shorten_by=1):
    out_list = []
    shortened_list = sorted([".".join(k.split(".")[:shorten_by*-1]) + "." for k in key_list],key=len)
    for k in shortened_list:
        found = False
        for out_key in out_list:
            if k.startswith(out_key):
                found = True
                break
        if not found:
            out_list.append(k)

    return out_list

def get_addobject_list(config_dict,parameternames_dict):
    # Generate a set of Addobject calls if needed.
    addobject_set = set()

    config_keys = list(config_dict)
    parameternames_keys = list(parameternames_dict)

    missing_keys = set()

    # Iterate over each config_dict item at test if it exists
    # Skip config_keys that exist as exact matches.
    for config_key in config_dict.keys():
        if not config_key in parameternames_keys:
            missing_keys.add(config_key)

    print(f"Missing keys:{missing_keys}")
    # Process each missing config_key
    for config_key in missing_keys:
        config_key_elements = config_key.split(".")

        # Progressively lenghten configkey until we don't find a match anymore.
        for i in range(2,len(config_key_elements)):
            # If the last element is not an index, continue with the next length.
            if not config_key_elements[i-1].isnumeric(): continue

            # Construct the shortened config_key
            shortened_config_key = ".".join(config_key_elements[:i]) + "."
            #print(f"Testing: {shortened_config_key}")
            # If any item in paramternames_keys matches, continue to the next longer shortened_config_key
            if any([key.startswith(shortened_config_key) for key in parameternames_keys]):
                #print(f"Found {shortened_config_key}")
                continue

            #print("Missing: %s" % ".".join(config_key_elements[:i]) + ".")
            addobject_set.add((".".join(config_key_elements[:i-1]) + ".",config_key_elements[i-1]))
            #print()
            break

    # Return a sorted list of missing keys.
    return sorted(addobject_set,key=len)





