from django.urls import path

import acs.views

app_name = 'acs'

urlpatterns = [
    path('', acs.views.AcsServerView.as_view(), name='acs_server'),
    path('v2/', acs.views.AcsServerView2.as_view(), name='acs_server'),
    path('v2/wifi/', acs.views.AcsServerView2.as_view(), name='acs_server', kwargs={"access_domain": "wifi"},),
    path('v2/mobile/', acs.views.AcsServerView2.as_view(), name='acs_server', kwargs={"access_domain": "mobile"},),
    path('v2/mobile/cpe/', acs.views.AcsServerView2.as_view(), name='acs_server', kwargs={"access_domain": "mobile_cpe"},),
]

