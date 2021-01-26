import datetime
from urllib.parse import unquote
import json

from django.conf import settings
from django.core import signing
from django.db.models import Q
from django.http import HttpResponseRedirect, JsonResponse
from django.contrib.auth import models as auth_models
from django.utils import crypto, timezone
from django.utils.http import urlencode
import httpx

from jwt_auth import views as jwt_auth_views

from . import models as france_connect_models

## The User model could extended with:
#
#    provider = models.CharField(
#        _("provider"), max_length=2, choices=PROVIDER_CHOICES, default=PROVIDER_A_DOCK
#    )
#    provider_data = models.JSONField(blank=True, null=True)


def get_callback_redirect_uri(request):
    redirect_uri = settings.FRANCE_CONNECT_URL_CALLBACK
    next_url = request.GET.get("next")
    if next_url:
        redirect_uri += f"?next={next_url}"

    return redirect_uri


def france_connect_authorize(request):
    # Possible to set acr_values=eidas1 (eidas2 or eidas3) to filter on provider
    # of identities on a security level.
    if not request.GET.get("nonce"):
        return JsonResponse(
            {"message": "The 'nonce' parameter is not provided."}, status=400
        )

    redirect_uri = get_callback_redirect_uri(request)

    signer = signing.Signer()
    csrf_string = crypto.get_random_string(length=12)
    csrf_signed = signer.sign(csrf_string)
    france_connect_models.FranceConnectState.objects.create(csrf_string=csrf_string)

    data = {
        "client_id": settings.FRANCE_CONNECT_CLIENT_ID,
        "nonce": request.GET["nonce"],
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid gender given_name family_name email address phone",
        "state": csrf_signed,
    }
    return HttpResponseRedirect(
        settings.FRANCE_CONNECT_URLS["authorize"] + "?" + urlencode(data)
    )


def create_or_update_user(user_infos):
    if "address" in user_infos and "formatted" in user_infos["address"]:
        user_infos["address"] = user_infos["address"]["formatted"]

    user, created = auth_models.User.objects.get_or_create(
        username=user_infos["sub"],
        defaults={
            "email": user_infos["email"],
            "first_name": user_infos.get("given_name", ""),
            "last_name": user_infos.get("family_name", ""),
            # "provider": auth_models.PROVIDER_FRANCE_CONNECT,
            # "provider_data": user_infos,
            # "is_confirmed": True,
        },
    )

    if not created:
        # Forced update (may be it will possible to set a different email later)
        user.email = user_infos.get("email", "")
        user.first_name = user_infos.get("given_name", "")
        user.family_name = user_infos.get("family_name", "")
        # user.provider = accounts_models.PROVIDER_FRANCE_CONNECT
        # user.provider_data = user_infos
        #
        user.save()

    return user, created


def state_is_valid(state):
    if not state:
        return False

    signer = signing.Signer()
    try:
        csrf_string = signer.unsign(unquote(state))
    except signing.BadSignature:
        return False

    try:
        france_connect_models.FranceConnectState.objects.get(csrf_string=csrf_string)
    except france_connect_models.FranceConnectState.DoesNotExist as e:
        # sentry_sdk.capture_exception(e)
        return False
    except france_connect_models.FranceConnectState.MultipleObjectsReturned:
        # sentry_sdk.capture_exception(e)
        return False

    france_connect_models.FranceConnectState.objects.filter(
        Q(created_at__lte=timezone.now() - datetime.timedelta(hours=1))
        | Q(csrf_string=csrf_string)
    ).delete()
    return True


def france_connect_callback(request):  # pylint: disable=too-many-return-statements
    # state is also available and should be checked (#1)
    code = request.GET.get("code")
    if code is None:
        return JsonResponse(
            {"message": "La requête ne contient pas le paramètre « code »."}, status=400
        )

    state = request.GET.get("state")
    if not state_is_valid(state):
        return JsonResponse(
            {"message": "Le paramètre « state » n'est pas valide."}, status=400
        )

    redirect_uri = get_callback_redirect_uri(request)

    data = {
        "client_id": settings.FRANCE_CONNECT_CLIENT_ID,
        "client_secret": settings.FRANCE_CONNECT_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }

    # Exceptions catched by Sentry
    response = httpx.post(settings.FRANCE_CONNECT_URLS["token"], data=data, timeout=60)

    if response.status_code != 200:
        message = "Impossible d'obtenir le jeton de FranceConnect."
        # sentry_sdk.capture_message(f"{message}\n{response.content}")
        # The response is certainly ignored by FC but it's convenient for our tests
        return JsonResponse({"message": message}, status=response.status_code)

    # Contains access_token, token_type, expires_in, id_token
    token_data = response.json()
    # A token has been provided so it's time to fetch associated user infos
    # because the token is only valid for 5 seconds.
    response = httpx.get(
        settings.FRANCE_CONNECT_URLS["userinfo"],
        params={"schema": "openid"},
        headers={"Authorization": "Bearer " + token_data["access_token"]},
        timeout=60,
    )
    if response.status_code != 200:
        message = "Impossible d'obtenir les informations utilisateur de FranceConnect."
        # sentry_sdk.capture_message(message)
        return JsonResponse({"message": message}, status=response.status_code)

    try:
        user_infos = json.loads(response.content.decode("utf-8"))
    except json.decoder.JSONDecodeError:
        return JsonResponse(
            {"message": "Impossible de décoder les informations utilisateur."},
            status=400,
        )

    if "sub" not in user_infos:
        return JsonResponse(
            {"message": "Le paramètre « sub » n'a pas été retourné par FranceConnect."},
            status=400,
        )

    user, created = create_or_update_user(user_infos)
    if created:
        # Send an email
        pass

    # Return JWT with id_token to allow logout from FC
    if user is None:
        return JsonResponse({"message": "Aucun utilisateur."})

    return JsonResponse(
        {
            "token_type": token_data.get("token_type", ""),
            "token": jwt_auth_views.jwt_encode_token(user),
            "expires_in": settings.JWT_EXPIRATION_DELTA.total_seconds(),
            "id_token": token_data.get("id_token", ""),
        }
    )


def france_connect_logout(request):
    if request.user.is_anonymous:
        return JsonResponse({"message": "L'utilisateur n'est pas authentifié."})

    id_token = request.GET.get("id_token")
    if not id_token:
        return JsonResponse(
            {"message": "Le paramètre « id_token » est manquant."}, status=400
        )

    params = {
        "id_token_hint": id_token,
        "state": "adock",
        "post_logout_redirect_uri": settings.FRANCE_CONNECT_URL_POST_LOGOUT,
    }
    redirect_url = settings.FRANCE_CONNECT_URLS["logout"] + "/?" + urlencode(params)
    return JsonResponse({"url": redirect_url}, status=302)
