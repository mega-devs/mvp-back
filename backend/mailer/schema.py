from drf_spectacular.extensions import OpenApiViewExtension
from drf_spectacular.utils import extend_schema, OpenApiExample

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