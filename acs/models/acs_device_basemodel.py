from acs.models import AcsBaseModel
from django.conf import settings


class AcsDeviceBaseModel(AcsBaseModel):
    class Meta:
        abstract = True

    def verify_acs_client_ip(self, ip):
        """
        Method to verify the ACS client IP, override in your own models.
        """
        raise NotImplementedError

    def is_configurable(self):
        """
        Method to determine if an acsdevice is configurable, override in your own models.
        """
        raise NotImplementedError

    def acs_session_pre_verify_hook(self):
        """
        This method is called every time an ACS device runs an ACS session,
        before verify_acs_client_ip() is called. Override in your own models as needed.
        """
        return False

    def acs_session_post_verify_hook(self):
        """
        This method is called every time an ACS device runs an ACS session,
        after verify_acs_client_ip() is called. Override in your own models as needed.
        """
        return False

    def get_acs_config(self):
        """
        This method is called while configuring an ACS device.
        Override in your own models to add device specific config
        Returns a dict to be merged with generic ACS client configuration.
        Keys must be present in acs_device.model.acs_parameter_map so we know where to put them
        """
        raise NotImplementedError

    def get_user_config_changelist(self):
        """
        This method should acs_device.acs_parameters versus the local records and returns a list of changed elements,
        if any. Should return an empty list if everything in acs_parameters matches the local records.
        """
        raise NotImplementedError

    def handle_user_config_change(self):
        """
        Called whenever the configuration on an ACS device is different from what we configured on it.
        """
        raise NotImplementedError

    def get_supported_rpc_methods(self):
        """
        Returns a list of rpc methods that the device supports (i.e. calls that the acs server can use).
        Some devices might not support all. Override if that is the case.
        """
        return settings.CWMP_CPE_VALID_RPC_METHODS

