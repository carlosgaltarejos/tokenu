from django.urls import path
from .views import TokenizeFileView, upload_file_form, view_token_form, show_wallet, view_token, home

urlpatterns = [
    path('', home, name='home'),  # Ruta para la página de inicio
    path('upload/', upload_file_form, name='upload-file-form'),
    path('tokenize/', TokenizeFileView.as_view(), name='tokenize-file'),
    path('view-token/', view_token_form, name='view-token-form'),
    path('show-wallet/', show_wallet, name='show-wallet'),
    path('view-token/', view_token, name='view-token'),
]
