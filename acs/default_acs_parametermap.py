# This dict contains the default mapping between the internal django-acs representation of attributes,
# and the actual name of the parameter in the xml tree.

default_acs_device_parametermap = {
    # acs server stuff
    "django_acs.acs.informinterval": "ManagementServer.PeriodicInformInterval",
    "django_acs.acs.acs_managed_upgrades": "ManagementServer.UpgradesManaged",
    "django_acs.acs.connection_request_user": "ManagementServer.ConnectionRequestUsername",
    "django_acs.acs.connection_request_password": "ManagementServer.ConnectionRequestPassword",
    "django_acs.acs.parameterkey": "ManagementServer.ParameterKey",
    "django_acs.acs.connrequrl": "ManagementServer.ConnectionRequestURL",

    # acs server xmpp stuff
    "django_acs.acs.xmpp_server": "XMPP.Connection.1.Server.1.ServerAddress",
    "django_acs.acs.xmpp_server_port": "XMPP.Connection.1.Server.1.Port",
    "django_acs.acs.xmpp_connection_enable": "XMPP.Connection.1.Enable",
    "django_acs.acs.xmpp_connection_username": "XMPP.Connection.1.Username",
    "django_acs.acs.xmpp_connection_password": "XMPP.Connection.1.Password",
    "django_acs.acs.xmpp_connection_domain": "XMPP.Connection.1.Domain",
    "django_acs.acs.xmpp_connection_usetls": "XMPP.Connection.1.UseTLS",
    "django_acs.acs.xmpp_connreq_connection": "ManagementServer.ConnReqXMPPConnection",

    # device info
    "django_acs.deviceinfo.softwareversion": "DeviceInfo.SoftwareVersion",
    "django_acs.deviceinfo.uptime": "DeviceInfo.UpTime",

    # wifi 2.4g
    "django_acs.wifi.bg_ssid": "WiFi.SSID.1.SSID",
    "django_acs.wifi.bg_wpapsk": "WiFi.AccessPoint.1.Security.KeyPassphrase",
    "django_acs.wifi.bg_autochannel": "WiFi.Radio.1.AutoChannelEnable",
    "django_acs.wifi.bg_channel": "WiFi.Radio.1.Channel",

    # wifi 5g
    "django_acs.wifi.n_ssid": "WiFi.SSID.5.SSID",
    "django_acs.wifi.n_wpapsk": "WiFi.AccessPoint.5.Security.KeyPassphrase",
    "django_acs.wifi.n_autochannel": "WiFi.Radio.2.AutoChannelEnable",
    "django_acs.wifi.n_channel": "WiFi.Radio.2.Channel",
}

### TR098 MAP

## Not used, just for reference.
beacon_acs_device_parametermap = {
    "django_acs.acs.acs_managed_upgrades": "ManagementServer.UpgradesManaged",
    "django_acs.acs.connection_request_password": "ManagementServer.ConnectionRequestPassword",
    "django_acs.acs.connection_request_user": "ManagementServer.ConnectionRequestUsername",
    "django_acs.acs.connrequrl": "ManagementServer.ConnectionRequestURL",
    "django_acs.acs.informinterval": "ManagementServer.PeriodicInformInterval",
    "django_acs.acs.parameterkey": "ManagementServer.ParameterKey",
    "django_acs.acs.xmpp_connection_domain": "XMPP.Connection.1.Domain",
    "django_acs.acs.xmpp_connection_enable": "XMPP.Connection.1.Enable",
    "django_acs.acs.xmpp_connection_password": "XMPP.Connection.1.Password",
    "django_acs.acs.xmpp_connection_username": "XMPP.Connection.1.Username",
    "django_acs.acs.xmpp_connection_usetls": "XMPP.Connection.1.UseTLS",
    "django_acs.acs.xmpp_connreq_connection": "",
    "django_acs.acs.xmpp_server": "XMPP.Connection.1.Resource",
    "django_acs.acs.xmpp_server_port": "XMPP.Connection.1.X_ALU_COM_XMPP_Port",
    "django_acs.deviceinfo.softwareversion": "DeviceInfo.SoftwareVersion",
    "django_acs.deviceinfo.uptime": "DeviceInfo.UpTime",
    "django_acs.management.ip.servicelist": "WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.X_D0542D_ServiceList",
    "django_acs.management.ip.https_disabled": "WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.X_ALU-COM_WanAccessCfg.HttpsDisabled",
    "django_acs.internet.vlan.id": "WANDevice.1.WANConnectionDevice.2.WANEthernetLinkConfig.X_ALU-COM_VLANIDMark",
    "django_acs.internet.vlan.mode": "WANDevice.1.WANConnectionDevice.2.WANEthernetLinkConfig.X_ALU-COM_Mode",
    "django_acs.internet.ip.type": "WANDevice.1.WANConnectionDevice.2.WANIPConnection.1.ConnectionType",
    "django_acs.internet.ip.enable": "WANDevice.1.WANConnectionDevice.2.WANIPConnection.1.Enable",
    "django_acs.internet.ip.servicelist": "WANDevice.1.WANConnectionDevice.2.WANIPConnection.1.X_D0542D_ServiceList",
    "django_acs.wifi.bg_algorithm": "",
    "django_acs.wifi.bg_ap_enable": "",
    "django_acs.wifi.bg_autochannel": "",
    "django_acs.wifi.bg_bandwidth": "",
    "django_acs.wifi.bg_channel": "LANDevice.1.WLANConfiguration.1.Channel",
    "django_acs.wifi.bg_enable": "LANDevice.1.WLANConfiguration.5.Enable",
    "django_acs.wifi.bg_mode": "",
    "django_acs.wifi.bg_securitymode": "",
    "django_acs.wifi.bg_ssid": "LANDevice.1.WLANConfiguration.1.SSID",
    "django_acs.wifi.bg_ssidbroadcast": "",
    "django_acs.wifi.bg_wpapsk": "LANDevice.1.WLANConfiguration.5.PreSharedKey.1.KeyPassphrase",
    "django_acs.wifi.n_algorithm": "",
    "django_acs.wifi.n_ap_enable": "",
    "django_acs.wifi.n_autochannel": "",
    "django_acs.wifi.n_bandwidth": "",
    "django_acs.wifi.n_channel": "LANDevice.1.WLANConfiguration.5.Channel",
    "django_acs.wifi.n_enable": "LANDevice.1.WLANConfiguration.1.Enable",
    "django_acs.wifi.n_mode": "",
    "django_acs.wifi.n_securitymode": "",
    "django_acs.wifi.n_ssid": "LANDevice.1.WLANConfiguration.5.SSID",
    "django_acs.wifi.n_ssidbroadcast": "",
    "django_acs.wifi.n_wpapsk": "LANDevice.1.WLANConfiguration.1.PreSharedKey.1.KeyPassphrase"
}

