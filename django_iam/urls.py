from django.urls import path

from . import views

urlpatterns = [
    path("api/session/authenticate/", views.authenticate_session, name="iam-authenticate"),
    path("api/session/public-key/", views.public_key, name="iam-public-key"),
    path("api/enforce/", views.enforce_batch, name="iam-enforce"),
]
