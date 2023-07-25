from django.urls import path , include
from  . import views

urlpatterns = [
    path("" , views.home ),
    path("pdf" , views.pdfParser ),
    path('signup', views.signup),
    path('login', views.login_view),
    path('logout', views.logout_view),
    path('recored', views.getRecords),
    path('send_otp', views.send_otp),
    path('verify_otp', views.verify_otp),
    path('reset_password', views.reset_password),
    
]
