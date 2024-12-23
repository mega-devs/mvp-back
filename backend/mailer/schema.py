from drf_spectacular.extensions import OpenApiViewExtension
from drf_spectacular.utils import extend_schema, OpenApiExample
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions

class MaterialViewExtension(OpenApiViewExtension):
    target_class = 'mailer.views.MaterialListView'

    def view_replacement(self):
        class Extended(self.target_class):
            @extend_schema(
                examples=[
                    OpenApiExample(
                        'SMTP список',
                        value=[{
                            'id': 1,
                            'server': 'smtp.gmail.com',
                            'port': 587,
                            'email': 'test@gmail.com',
                            'status': 'valid'
                        }]
                    ),
                ]
            )
            def get(self, request, *args, **kwargs):
                pass

        return Extended 

schema_view = get_schema_view(
    openapi.Info(
        title="Mailer API",
        default_version='v1',
        description="API для системы рассылки email",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="contact@mail.local"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=[permissions.AllowAny],
)