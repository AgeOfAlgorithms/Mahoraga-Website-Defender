#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""
contains all the views related to Merchant
"""
import json
import logging
import requests
from requests.exceptions import MissingSchema, InvalidURL
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from crapi.user.serializers import UserDetailsSerializer
from crapi.user.models import User, UserDetails
from crapi_site import settings
from utils.jwt import jwt_auth_required
from utils import messages
from utils.logging import log_error
from rest_framework.pagination import LimitOffsetPagination
import jwt as pyjwt

logger = logging.getLogger()


class AdminUserView(APIView, LimitOffsetPagination):
    """
    View for admin user to fetch user details
    """

    @jwt_auth_required
    def get(self, request, user=None):
        """
        Admin user view to fetch user details
        :param request: http request for the view
            method allowed: GET
            http request should be authorised by the jwt token of the user
            mandatory fields: []
        :returns Response object with
            user details and 200 status if no error
            message and corresponding status if error
        """
        # Sort by id
        userdetails = UserDetails.objects.all().order_by("id")
        if not userdetails:
            return Response(
                {"message": messages.NO_USER_DETAILS}, status=status.HTTP_404_NOT_FOUND
            )
        paginated = self.paginate_queryset(userdetails, request)
        serializer = UserDetailsSerializer(paginated, many=True)
        response_data = dict(
            users=serializer.data,
            next_offset=(
                self.offset + self.limit
                if self.offset + self.limit < self.count
                else None
            ),
            previous_offset=(
                self.offset - self.limit if self.offset - self.limit >= 0 else None
            ),
            count=self.get_count(paginated),
        )
        return Response(response_data, status=status.HTTP_200_OK)


class ManagementDashboardView(APIView):
    """Fleet management dashboard — admin only.

    Intentional vulnerability: decodes JWT without full verification,
    allowing algorithm confusion attacks (e.g., alg:none, HS256/RS256 swap).
    """

    @jwt_auth_required
    def get(self, request, user=None):
        auth = request.META.get("HTTP_AUTHORIZATION", "")
        token = auth[7:]
        try:
            decoded = pyjwt.decode(
                token,
                options={"verify_signature": False},
                algorithms=["RS256", "HS256"],
            )
        except pyjwt.exceptions.DecodeError:
            return Response(
                {"message": "Invalid token"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        role = decoded.get("role", "")
        if role not in ("ROLE_ADMIN", "admin"):
            return Response(
                {"message": "Insufficient privileges", "your_role": role},
                status=status.HTTP_403_FORBIDDEN,
            )

        response_data = {
            "dashboard": "VehiTrack Fleet Management",
            "status": "operational",
            "fleet_size": 847,
            "active_vehicles": 623,
            "maintenance_queue": 31,
            "admin_user": decoded.get("sub", ""),
        }

        # Check if token was forged (alg:none or unsigned)
        import base64
        try:
            header_b64 = token.split(".")[0]
            header_b64 += "=" * (-len(header_b64) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            if header.get("alg", "").lower() in ("none", ""):
                response_data["_internal_audit"] = "XVEH{jwt_alg_swap_priv_esc_c81d}"
        except Exception:
            pass

        return Response(response_data)


class ManagementKeysView(APIView):
    """Internal API key management — requires staging API key."""

    VALID_KEY = "vtrk-web-f84a2c01"

    def get(self, request):
        api_key = (
            request.META.get("HTTP_X_API_KEY", "")
            or request.META.get("HTTP_X_INTERNAL_KEY", "")
        )

        if not api_key:
            return Response(
                {"message": "API key required. Use X-Api-Key header."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if api_key != self.VALID_KEY:
            return Response(
                {"message": "Invalid API key"},
                status=status.HTTP_403_FORBIDDEN,
            )

        return Response({
            "environment": "staging",
            "keys": [
                {
                    "name": "fleet-api-primary",
                    "key": "xveh-sk-83d2e6f1a47b09c5",
                    "scope": "read:fleet,write:vehicles",
                    "created": "2025-11-03",
                },
                {
                    "name": "internal-service-mesh",
                    "key": "XVEH{staging_key_dump_4f9a}",
                    "scope": "admin:all",
                    "created": "2025-09-18",
                },
            ],
            "_warning": "Staging keys — rotate before production deployment",
        })


class FleetStatusView(APIView):
    """Internal fleet monitoring — reachable via SSRF only.

    The attacker discovers this by using SSRF to probe crapi-workshop:8000
    internal paths. Contains the SSRF/internal discovery flag.
    """

    def get(self, request):
        return Response({
            "service": "VehiTrack Fleet Monitor",
            "version": "3.2.1-internal",
            "fleet": {
                "total_vehicles": 847,
                "active_tracking": 623,
                "offline": 224,
            },
            "connected_services": [
                {"name": "crapi-identity", "port": 8080, "status": "healthy"},
                {"name": "crapi-community", "port": 8087, "status": "healthy"},
                {"name": "postgresdb", "port": 5432, "status": "healthy"},
                {"name": "mongodb", "port": 27017, "status": "healthy"},
            ],
            "internal_mesh_key": "XVEH{internal_net_mapped_91fa}",
            "_note": "Internal service mesh — not for external access.",
        })
