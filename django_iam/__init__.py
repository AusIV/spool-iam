default_app_config = "django_iam.apps.DjangoIamConfig"

def enforce(*args, **kwargs):
    from .enforcement import enforce as _enforce

    return _enforce(*args, **kwargs)
