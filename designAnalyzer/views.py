from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth import login , authenticate,logout
from .forms import CustomUserCreationForm
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.conf import settings
from rest_framework import status
from .models import PdfResult
from .serializers import pdfParserSerializer
from django.middleware import csrf
from datetime import datetime, timedelta
from .models import PdfResult , CustomUser
from django.core.mail import send_mail
import random


import jwt
import json
import fitz 
import time                      
import io                        
from PIL import Image      
import re

def home(request):
    return render(request , 'index.html')

@csrf_exempt   
def signup(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            response_data = {
                'success': True,
                'message': 'Registration successful',
            }
            return JsonResponse(response_data)
        else:
            response_data = {
                'success': False,
                'errors': form.errors
            }
            return JsonResponse(response_data, status=400)
    else:
        response_data = {
            'success': False,
            'message': 'Invalid request method'
        }
        return JsonResponse(response_data, status=405)

@csrf_exempt
def login_view(request):
    if request.method == 'POST':
        try:
            body = json.loads(request.body)
            email = body.get('email')
            password = body.get('password')
            print(email,password)
            try:
                user = CustomUser.objects.get(email=email)
            except CustomUser.DoesNotExist:
                return JsonResponse({'success': False, 'message': 'Invalid email or password'}, status=401)

            if user.check_password(password):
                user_detail = {
                    'username': user.username,
                    'email': user.email,
                }
                login(request, user)
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)

                response = JsonResponse({'success': True, "userAccessToken": access_token, "user": user_detail, 'message': 'Login successful'})
                expires = datetime.utcnow() + timedelta(days=2)

                response.set_cookie(
                    key=settings.SIMPLE_JWT['AUTH_COOKIE'],
                    value=access_token,
                    expires=expires,
                    secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                    httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                    samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
                )

                return response
            else:
                return JsonResponse({'success': False, 'message': 'Invalid email or password'}, status=401)
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'message': 'Invalid JSON data'}, status=400)
    else:
        return JsonResponse({'success': False, 'message': 'Invalid request method'}, status=405)


@permission_classes([IsAuthenticated])
@csrf_exempt
def logout_view(request):
    logout(request)
    response = JsonResponse({'success': True, 'message': 'Logout successful'})
    response.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE'])
    return response
    

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@csrf_exempt    
def pdfParser(request):
    if request.method == 'POST' and request.FILES.get('pdf-file'):
        file = request.FILES['pdf-file']
        size = request.POST.get('size')
        type = request.POST.get('type')
        metarial = request.POST.get('metarial')
        page_size = json.loads(size)
        start = time.time()
        doc = fitz.open(stream=file.read(), filetype='pdf') 
        version = doc.metadata["format"]
        version_str = doc.metadata["format"]
        match = re.search(r'\d+\.\d+', version_str)
        result = []  
        status = True
        if match:
            version = float(match.group())
            if version > 1.5:
                result.append({
                    "name": "File Version",
                    "status": "SUCCESS",
                    "Config min. version": "1.6",
                    "Artwork PDF version": version
                })
            else:
                status = False
                result.append({
                    "name": "File Version",
                    "status": "FAILED",
                    "Config min. version": "1.6",
                    "Artwork PDF version": version
                })
        else:
            status = False
            result.append({
                    "name": "File Version",
                    "status": "FAILED",
                    "Config min. version": "1.6",
                    "Error": f"Could not extract version number from string: {version_str}"
            })
            
        page = doc[0]  
        page_number = page.number + 1
        text = doc.get_page_text(page.number)
        image_list = page.get_images()
        page_height = round(page.rect.height / 2.835)
        page_width = round(page.rect.width / 2.835)
        w,h = page_size
        if (w,h) == ( page_width,page_height):
            result.append({
                    "name":"Dimensions",
                    "status": "SUCCESS",
                    "Config width": w,
                    "Config height": h,
                    "Artwork width": page_width,
                    "Artwork height": page_height
            })
        else:
            status = False
            print(status)
            result.append({
                    "name":"Dimensions",                    
                    "status": "FAILED",
                    "Config width": w,
                    "Config height": h,
                    "Artwork width": page_width,
                    "Artwork height": page_height
            })
        if text:
            status = False
            result.append({
                    "name":"Font",
                    "status": "FAILED",
                    "Message": "Text found in Artwork"
            })
        else:
            result.append({
                    "name":"Font",
                    "status": "SUCCESS",
                    "Message": "No text found in Artwork"
            })

        layouts = doc.get_ocgs()
        arr = []
        missing_layers = []

        for k, v in layouts.items():
            if v["name"] == "bila-white" or v["name"] == "Artwork":
                arr.append(v["name"])
        if "Artwork" not in arr:
            missing_layers.append("Artwork")
        if "bila-white" not in arr:
            missing_layers.append("bila-white")

        if missing_layers:
            status = False
            result.append({
                "name": "Layers",
                "status": "FAILED",
                "missing": missing_layers,
                "Message": "Artwork or bila-white or both missing"
            })
        else:
            result.append({
                "name": "Layers",
                "status": "SUCCESS",
                "Config mandatory layers": "Artwork and bila-white",
                "Detected layers": "Artwork and bila-white"
            })

        success = "SUCCESS" 
        colorStatus = "SUCCESS"  
        for img in image_list:
            info = page.get_image_info(hashes=True)
            bbox = info[0]['bbox']
            width_inches = (bbox[2] - bbox[0]) / 72.0
            height_inches = (bbox[3] - bbox[1]) / 72.0
            width_pixels = info[0]['width']
            height_pixels = info[0]['height']
            colorspace = info[0]['cs-name']
            print(colorspace)
            dpi_x = round(width_pixels / width_inches, 2)
            dpi_y = round(height_pixels / height_inches, 2)
            if colorspace != "DeviceCMYK" and colorspace != "Indexed(255,DeviceCMYK)" :
                colorStatus ="FAILED"
                print(colorStatus)
            if dpi_x < 300 or dpi_y < 300:
                success = "FAILED"  # Set success to False if any image doesn't meet the criteria

        result.append({
                "name": "Image DPI",
                "status": success,
                "config" :" DPI >= 300"
            })
        print(colorStatus)
        result.append({
                    "name": "Image Color",
                    "status": colorStatus,
                    "config" :"CMYK Model"
                })

    result.append({
            "name": "Execution Time",
            "costTime":  round(time.time() - start, 3)
    })
    
    json_string = json.dumps(result)    
    pdf_result = PdfResult(file_name=file.name,user = request.user, result=result , status =status)
    pdf_result.save()
    response_data = {
                        'message': 'File uploaded successfully',
                        'data': json.loads(json_string),  
                    }
    return HttpResponse(json.dumps(response_data) ,content_type='application/json')


@api_view(['GET'])
# @permission_classes([IsAuthenticated])
# @login_required

def getRecords(request):
    try:
        print(request.user)
        records = PdfResult.objects.filter(user=request.user)
        serializer = pdfParserSerializer(records, many=True)
        response_data = {'message': 'Success', 'data': serializer.data}
        json_data = json.dumps(response_data)
        return HttpResponse(json_data, content_type='application/json', status=200)
    except Exception as e:
        error_message = str(e)
        response_data = {'message': 'Error', 'error': error_message}
        json_data = json.dumps(response_data)
        return HttpResponse(json_data, content_type='application/json', status=500)


@api_view(['POST'])
def send_otp(request):
    email = request.data.get('email')  
    try:
        user = CustomUser.objects.get(email=email)
    except CustomUser.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'User does not exist'})
    otp = str(random.randint(100000, 999999))
    user.otp = otp
    user.save()
    subject = 'OTP Verification'
    message = f'Your OTP is: {otp}'
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, from_email, recipient_list)

    response_data = {
        'success': True,
        'message': 'OTP sent successfully',
        # Other data you want to include in the response
    }

    return JsonResponse(response_data)

from django.http import HttpResponseBadRequest

@api_view(['POST'])
def verify_otp(request):
    email = request.data.get('email')
    otp = request.data.get('otp')
    try:
        user = CustomUser.objects.get(email=email)
    except CustomUser.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'User does not exist'}, status=404)

    if str(user.otp) == str(otp):
        user.otp = None
        user.save()
        return JsonResponse({'success': True, 'message': 'OTP verified and password reset allowed'}, status=200)
    else:
        return JsonResponse({'success': False, 'message': 'Invalid OTP'}, status=400)



@api_view(['POST'])
def reset_password(request):
    email = request.data.get('email')
    print(email)
    new_password = request.data.get('newPassword')
    confirm_password = request.data.get('confirmPassword')

    if new_password != confirm_password:
        return JsonResponse({'success': False, 'message': 'Passwords do not match'})

    try:
        user = CustomUser.objects.get(email=email)
    except CustomUser.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'User does not exist'})

    user.set_password(new_password)
    user.save()
    return JsonResponse({'success': True, 'message': 'Password reset successful'})
