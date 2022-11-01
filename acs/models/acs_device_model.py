from acs.models import AcsBaseModel
from django.urls import reverse
from django.contrib.postgres.fields import JSONField
from django.conf import settings
from django.db import models
from acs.default_acs_parametermap import default_acs_device_parametermap

class AcsDeviceModel(AcsBaseModel):
    vendor = models.ForeignKey('acs.AcsDeviceVendor', related_name='acsdevicemodels', on_delete=models.PROTECT)
    category = models.ForeignKey('acs.AcsDeviceCategory', related_name='acsdevicemodels', default=1, on_delete=models.PROTECT)
    name = models.CharField(max_length=50)
    desired_config_level = models.DateTimeField(null=True, blank=True)
    desired_software_version = models.CharField(max_length=50, blank=True)
    acs_parameter_map_overrides = JSONField(null=True, blank=True)
    acs_connectionrequest_digest_auth = models.BooleanField(default=False)
    xmpp_template = models.TextField(blank=True, default="")
    preconfig_template = models.TextField(blank=True, default="")
    config_template = models.TextField(blank=True, default="")
    tracked_parameters = models.TextField(blank=True, default="")


    def __str__(self):
        return str("%s - %s" % (self.tag, self.name))

    def get_absolute_url(self):
        return reverse('acsdevicemodel_detail', kwargs={'pk': self.pk})

    @property
    def acs_parameter_map(self):
        # return the default_acs_device_parametermap with the overrides for this specific device
        if self.acs_parameter_map_overrides:
            default_acs_device_parametermap.update(self.acs_parameter_map_overrides)
        return default_acs_device_parametermap

    def get_active_notification_parameterlist(self, root_object):
        """
        Return the list of parameters which needs active notifications,
        based on the category of devicemodel
        """
        parameterlist = []
        if self.category.name in ["WIFI", "MODEM"]:
            #This acs device category needs notifications for the whole Wifi tree
            parameterlist.append("%s.Wifi." % root_object)
        return parameterlist


