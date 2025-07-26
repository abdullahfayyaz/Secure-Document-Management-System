from django.shortcuts import render, redirect
import random
from django.core.mail import send_mail
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.timezone import now
from django.contrib.auth.hashers import make_password
from Crypto.PublicKey import RSA
from .models import User
from django.contrib.auth.hashers import check_password
from django.utils.timezone import now, timedelta
from django.contrib import messages
import base64
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import *
from django.utils import timezone
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import io, re
from django.shortcuts import get_object_or_404
from django.http import FileResponse, Http404
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os
import random
from Crypto.PublicKey import RSA
from django.utils.timezone import now
from django.contrib.auth.hashers import make_password
from django.db.models import Count
from .utils import get_client_ip, is_ip_blocked, register_failed_attempt, reset_ip_attempts
from django.shortcuts import render, redirect
from django.contrib import messages
from datetime import timedelta
from .models import User, Document, RiskLog, ClassificationResult, AccessLog
import base64
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.exceptions import InvalidSignature
from SecureDocAI.classify_pdf import classify_pdf_
import tempfile



@csrf_exempt
def home_view(request):
    request.session.flush()
    ip = get_client_ip(request)

    # # Check if IP is blocked
    if is_ip_blocked(ip):
        print('IP being blocked.')
        return redirect('home')

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        try:
            user = User.objects.get(username=username)

            # Check if user account is locked
            if user.lockout_until and user.lockout_until > timezone.now():
                RiskLog.objects.create(
                    user=user,
                    action='login',
                    description='Attempted login during lockout period',
                    risk_level='high',
                    ip_address=ip
                )
                messages.error(request, 'Account is temporarily locked. Try again later.')
                return redirect('home')

            # Validate password
            if not check_password(password, user.password):
                user.failed_login_attempts += 1
                user.save()

                # Account lockout logic
                if user.failed_login_attempts >= 5:
                    user.lockout_until = timezone.now() + timezone.timedelta(minutes=5)
                    user.save()

                    RiskLog.objects.create(
                        user=user,
                        action='login',
                        description='User account locked after 5 failed attempts',
                        risk_level='high',
                        ip_address=ip
                    )
                    messages.error(request, 'Account locked due to multiple failed attempts.')
                else:
                    RiskLog.objects.create(
                        user=user,
                        action='login',
                        description='Invalid password attempt',
                        risk_level='medium',
                        ip_address=ip
                    )
                    messages.error(request, 'Invalid password.')

                # Register failed attempt by IP
                if register_failed_attempt(ip):
                    # messages.error(request, 'Too many failed attempts from this IP. You are temporarily blocked.')
                    print('IP blocked')  
                return redirect('home')

            # Successful login
            user.failed_login_attempts = 0
            user.lockout_until = None
            user.save()

            # Reset IP attempts on successful login
            reset_ip_attempts(ip)

            # Generate OTP
            otp_code = f"{random.randint(100000, 999999)}"
            otp_time = timezone.now()
            user.otp_code = otp_code
            user.otp_created_at = otp_time
            user.save()

            # Send OTP email
            try:
                send_mail(
                    subject='Your SecureDocAI Login OTP',
                    message=f'Your OTP is: {otp_code}',
                    from_email='no-reply@securedocai.com',
                    recipient_list=[user.email],
                    fail_silently=False,
                )
            except Exception as e:
                messages.error(request, 'Failed to send OTP. Please try again.')
                return redirect('home')

            # Log login action
            AccessLog.objects.create(
                user=user,
                document=None,
                action='login',
                ip_address=ip,
            )

            # Save session info
            request.session['temp_user_id'] = str(user.id)
            request.session['temp_user_role'] = str(user.role)
            return redirect('mfa_verification')

        except User.DoesNotExist:
            messages.error(request, 'User not found.')
            # Register failed attempt by IP even if user doesn’t exist
            register_failed_attempt(ip)
            return redirect('home')

    return render(request, 'SecureDocAI/index.html')


def encrypt_private_key(private_key_bytes, password):
    password_bytes = password.encode()
    salt = os.urandom(16) 
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    f = Fernet(key)
    encrypted_private_key = f.encrypt(private_key_bytes)

    return base64.b64encode(salt + encrypted_private_key).decode()


def decrypt_private_key(encrypted_data_base64, password):
    encrypted_data = base64.b64decode(encrypted_data_base64)
    salt = encrypted_data[:16]
    encrypted_key = encrypted_data[16:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    f = Fernet(key)
    return f.decrypt(encrypted_key)


from django.core.validators import validate_email
from django.core.exceptions import ValidationError
import dns.resolver

@csrf_exempt
def signup_view(request):

    if request.method == 'POST':
        try:    
            username = request.POST.get('username')
            email = request.POST.get('email')
            role = request.POST.get('role')
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')

        # Password validation
            if password != confirm_password:
                messages.error(request, 'Passwords do not match!')
                return redirect('signup')
        
            if len(password) < 8:
                messages.error(request, 'Password must be at least 8 characters long!')
                return redirect('signup')
            if not re.search(r'[A-Z]', password):
                messages.error(request, 'Password must contain at least one uppercase letter!')
                return redirect('signup')
            
            if not re.search(r'[a-z]', password):
                messages.error(request, 'Password must contain at least one lowercase letter!')
                return redirect('signup')
            
            if not re.search(r'\d', password):
                messages.error(request, 'Password must contain at least one digit!')
                return redirect('signup')
            
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                messages.error(request, 'Password must contain at least one special character!')
                return redirect('signup')

            if not role:
                messages.error(request, 'Please select a role!')
                return redirect('signup')
                

            if User.objects.filter(username=username).exists():
                messages.error(request, 'Username already exists')
                return redirect('signup')
                

            from django.core.validators import validate_email
            from django.core.exceptions import ValidationError
            import dns.resolver

# 1. Check if email already exists in DB
            if User.objects.filter(email=email).exists():
                messages.error(request, 'Email already registered')
                return redirect('signup')

# 2. Basic email format check
            try:
                validate_email(email)
            except ValidationError:
                messages.error(request, 'Invalid email format!')
                return redirect('signup')

# 3. Optional DNS check for email domain
            domain = email.split('@')[-1]
            try:
                dns.resolver.resolve(domain, 'MX')  # check if domain has mail servers
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                messages.error(request, 'Email domain is not valid!')
                return redirect('signup')


            # Generate RSA key pair
            key = RSA.generate(2048)
            private_key = key.export_key()
            public_key = key.publickey().export_key()


            # Generate OTP
            otp_code = f"{random.randint(100000, 999999)}"
            otp_time = now()

            try:
                send_mail(
            subject='Your SecureDocAI OTP Code',
            message=f'Your OTP is: {otp_code}',
            from_email='no-reply@securedocai.com',
            recipient_list=[email],
            fail_silently=False,
            )
            except Exception as e:
                messages.error(request, 'Failed to send OTP. Please check your email address.')
                return redirect('signup')

            p1 = make_password(password)            
            user = User.objects.create(
                username=username,
                email=email,
                password=p1,
                role=role,
                rsa_public_key=public_key.decode(),
                rsa_private_key_encrypted=encrypt_private_key(private_key, p1),
                otp_code=otp_code,
                otp_created_at=otp_time,
                is_verified=False,
            )
            request.session['temp_user_id'] = str(user.id)
            request.session['temp_user_role'] = str(user.role)            
            return redirect('mfa_verification')

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return render(request, 'SecureDocAI/signup.html', {'error': None})

@csrf_exempt
def otp_verification(request):
    if request.method == 'POST':
        entered_otp = request.POST.get('otp')

        user_id = request.session.get('temp_user_id')
        if not user_id:
            messages.error(request, 'Session expired. Please sign up again.')
            return redirect('mfa_verification')
            
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=400)

        # Check OTP match and expiry (e.g., valid for 10 minutes)
        if user.otp_code == entered_otp and user.otp_created_at + timedelta(minutes=10) > now():
            user.is_verified = True
            user.otp_code = None
            user.save()
            return redirect("mfa_verification_success")
        else:
            messages.error(request, 'Invalid or expired OTP')
            return redirect('mfa_verification')
            
    return render(request, 'SecureDocAI/mfa.html')


def view_success(request):
    return render(request, 'SecureDocAI/success.html')

def logout_view(request):
    request.session.flush()
    return redirect('home')  # Redirect to login page

def dashboard_view(request):
    user_id = request.session.get('temp_user_id') 
    user_role = request.session.get('temp_user_role')
    print(user_role)
    if user_role == 'admin':
        return redirect('admin_dashboard')
    if user_role == 'reviewer':
        return redirect('reviewer_dashboard')
    if user_role == "uploader":
        return redirect('uploader_dashboard')        

    return redirect('dashboard')

def admin_deashboard_view(request):
    total_uploaders = User.objects.filter(role='uploader').count()
    total_reviewers = User.objects.filter(role='reviewer').count()
    total_documents = Document.objects.count()
    pending_requests = ReviewRequest.objects.filter(status='pending').count()

    context = {
        'total_uploaders': total_uploaders,
        'total_reviewers': total_reviewers,
        'total_documents': total_documents,
        'pending_requests': pending_requests,
    }
    return render(request, 'SecureDocAI/admin/dashboard.html', context=context)    

def admin_DocReq_view(request):
    documents = Document.objects.all().annotate(
        access_count=Count('accesslog')
    ).select_related('uploader')
    
    context = {
        'documents': documents
    }
    return render(request, 'SecureDocAI/admin/document.html', context=context)


# view regarding request accepting or dening.
def admin_Request_view(request):
    review_requests = ReviewRequest.objects.select_related('reviewer', 'document').all().order_by('-requested_at')
    context = {
        'review_requests': review_requests
    }
    return render(request, 'SecureDocAI/admin/requests.html', context=context)

def update_review_status(request):
    request_id = request.GET.get("request_id")
    action = request.GET.get("action")

    review_request = get_object_or_404(ReviewRequest, id=request_id)

    if action == "accept":
        review_request.status = "accepted"
    elif action == "deny":
        review_request.status = "denied"
    else:
        messages.error(request, "Invalid action.")
        return redirect("admin_Requests")

    review_request.reviewed_at = timezone.now()
    
    if action == "accept":
        share_document_with_reviewer(request, review_request.document.id, review_request.reviewer.id, review_request.document.uploader.id)

    AccessLog.objects.create(
        user=review_request.reviewer,
        document=review_request.document,
        action='review_status',
        ip_address=request.META.get('REMOTE_ADDR'),
        metadata=None
        )    
    review_request.save()
    messages.success(request, f"Request has been {action}ed.")
    return redirect("admin_Requests")



def share_document_with_reviewer(request, doc_id, reviewer_id, uploader_id):
    try:
        uploader = User.objects.get(id=uploader_id)
        document = Document.objects.get(pk=doc_id, uploader=uploader)
        reviewer = User.objects.get(pk=reviewer_id, role='reviewer')
        

        # 1. Decrypt uploader's private key

        decrypted_private_key_pem = decrypt_private_key(uploader.rsa_private_key_encrypted, uploader.password)
        private_key = serialization.load_pem_private_key(decrypted_private_key_pem, password=None)

        # 2. Decrypt AES key using uploader's private key
        aes_key = private_key.decrypt(
            document.encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )

        # 3. Load reviewer’s public key
        reviewer_public_key = serialization.load_pem_public_key(
            reviewer.rsa_public_key.encode()
        )

        # 4. Encrypt AES key with reviewer's public key
        re_encrypted_aes_key = reviewer_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        # 5. Save it in SharedKey
        SharedKey.objects.update_or_create(
            document=document,
            shared_with=reviewer,
            defaults={'encrypted_aes_key': re_encrypted_aes_key}
        )
        
        return 'success'

    except Exception as e:
            return 'error'



def admin_users_view(request):
    users = User.objects.exclude(role='admin')
    user_data = [
        {
            'username': user.username,
            'email': user.email,
            'role': user.get_role_display(),
            'date_joined': user.date_joined.strftime('%Y-%m-%d') if user.date_joined else '',
        }
        for user in users
    ]

    return render(request, 'SecureDocAI/admin/users.html', {'users': user_data})

def reviewer_dashboard_view(request):
    user = User.objects.get(pk=request.session.get('temp_user_id'))
    username = user.username

    documents = Document.objects.select_related('uploader').filter(is_available=True).order_by('-uploaded_at')

    content = {
        'user': username,
        'documents': documents
    }
    return render(request, 'SecureDocAI/reviewer/alldoc.html', context=content)


def reviewer_snd_request_view(request, document_id):
    document = get_object_or_404(Document, id=document_id)
    user = User.objects.get(pk=request.session.get('temp_user_id'))

# logic for risk log

    pending = ReviewRequest.objects.filter(reviewer=user, status='pending').count()

    if pending >= 3:
        RiskLog.objects.create(
            user=user,
            action='request_review',
            description='Reviewer has 3+ pending review requests',
            risk_level='medium',
            ip_address=request.META.get('REMOTE_ADDR')
        )
        messages.error(request, 'Too many pending requests')
        return redirect('reviewer_dashboard')

# logic for main functionality
    # Prevent multiple requests
    existing_request = ReviewRequest.objects.filter(reviewer=user, document=document).first()
    if not existing_request:
        ReviewRequest.objects.create(
            reviewer=user,
            document=document,
            status='pending'
        )
        AccessLog.objects.create(
        user=user,
        document=document,
        action='review_request',
        ip_address=request.META.get('REMOTE_ADDR'),
        metadata=None
        )
        messages.success(request, 'Access request sent!')
    else:
        messages.info(request, 'Request already pending.')

    return redirect('reviewer_dashboard')

def reviewer_my_doc_view(request):
    user = User.objects.get(pk=request.session.get('temp_user_id'))
    username = user.username

    accepted_requests = ReviewRequest.objects.filter(
        reviewer_id=user.id,
        status='accepted'
    ).select_related('document', 'document__uploader')

    # Extract documents
    documents = [req.document for req in accepted_requests]
    content = {
        'user': username,
        'documents': documents
    }
    
    return render(request, 'SecureDocAI/reviewer/mydoc.html', context= content)

def reviewer_request_view(request):
    user = User.objects.get(pk=request.session.get('temp_user_id'))
    review_requests = ReviewRequest.objects.filter(reviewer=user).select_related('document').order_by('-requested_at')

    username = user.username
    content = {
        'user': username,
        'review_requests': review_requests
    }
    return render(request, 'SecureDocAI/reviewer/request.html', context= content)

# uploader dashboard and also add document logic



def uploader_dashboard_view(request):
    user_id = request.session.get('temp_user_id')
    if not user_id:
        messages.error(request, "Session expired or invalid.")
        return redirect('login')

    user = User.objects.get(pk=user_id)
    documents = Document.objects.filter(uploader=user)

    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        encrypted_aes_key_b64 = request.POST.get('encrypted_aes_key')
        encrypted_metadata_b64 = request.POST.get('encrypted_metadata')
        uploaded_file = request.FILES.get('file')
        classification = request.POST.get('classification')  # Will be replaced by AI
        signature_b64 = request.POST.get('signature')
        signing_public_key_b64 = request.POST.get('signingPublicKey')

        if not uploaded_file:
            messages.error(request, "No file uploaded.")
            return redirect('uploader_dashboard')

        # Signature verification
        try:
            signature = base64.b64decode(signature_b64)
            public_key_der = base64.b64decode(signing_public_key_b64)
            public_key = serialization.load_der_public_key(public_key_der)

            public_key.verify(
                signature,
                title.encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except InvalidSignature:
            messages.error(request, "Signature verification failed.")
            return redirect('uploader_dashboard')
        except Exception as e:
            messages.error(request, f"Signature error: {str(e)}")
            return redirect('uploader_dashboard')

        # Risk logging
        one_minute_ago = datetime.now() - timedelta(minutes=1)
        uploads = Document.objects.filter(uploader=user, uploaded_at__gte=one_minute_ago).count()
        if uploads >= 5:
            RiskLog.objects.create(
                user=user,
                action='upload',
                description='Uploader uploaded 5+ documents within 1 minute',
                risk_level='medium',
                ip_address=request.META.get('REMOTE_ADDR')
            )

        encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
        encrypted_metadata = base64.b64decode(encrypted_metadata_b64)

        # Step 1: Decrypt AES key using user private key
        try:
            decrypted_private_key_pem = decrypt_private_key(user.rsa_private_key_encrypted, user.password)
            private_key = serialization.load_pem_private_key(decrypted_private_key_pem, password=None)
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None
                )
            )

            # Step 2: Decrypt file contents
            file_data = uploaded_file.read()
            iv = file_data[:12]
            ciphertext = file_data[12:-16]
            tag = file_data[-16:]

            decryptor = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(iv, tag)
            ).decryptor()

            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()


            with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as temp_pdf:
                temp_pdf.write(decrypted_data)
                temp_pdf_path = temp_pdf.name


            ai_classification = classify_pdf_(temp_pdf_path)
            classification = ai_classification

        except Exception as e:
            messages.error(request, f"Decryption or classification error: {str(e)}")
            return redirect('uploader_dashboard')


        document = Document.objects.create(
            uploader=user,
            title=title,
            description=description,
            encrypted_file=uploaded_file,
            encrypted_aes_key=encrypted_aes_key,
            encrypted_metadata=encrypted_metadata,
            classification=classification
        )

        ClassificationResult.objects.create(
            document=document,
            detected_keywords=[],  # optional: populate based on model
            ai_model_version="LogisticsRegression-v1",
            confidence_score=1.0  # optional: modify if model returns confidence
        )

        AccessLog.objects.create(
            user=user,
            document=document,
            action='upload',
            ip_address=request.META.get('REMOTE_ADDR'),
            metadata=None
        )

        messages.success(request, "Document uploaded, verified and classified successfully.")
        return redirect('uploader_dashboard')

    context = {
        'user': user.username,
        'key': user.rsa_public_key,
        'documents': documents
    }
    return render(request, 'SecureDocAI/uploader/uploadPage.html', context=context)


def uploader_viewdocument_view(request):
    user_id = request.session.get('temp_user_id')
    user = User.objects.get(pk=user_id)
    documents = Document.objects.filter(uploader=user,is_available=True)

    context = {
        'user': user.username,
        'key': user.rsa_public_key,
        'documents': documents
    }
    return render(request, 'SecureDocAI/uploader/viewdocument.html', context=context)
    

def uploader_accesslog_view(request):
    user = User.objects.get(pk=request.session.get('temp_user_id'))
    access_logs = AccessLog.objects.filter(user=user).select_related('document').order_by('-timestamp')

    username = user.username
    content = {
        'user': username,
        'access_logs': access_logs
    }    
    return render(request, 'SecureDocAI/uploader/accesslog.html', context=content)


import traceback

# for uploader
def view_document1(request, doc_id):
    try:
        user = User.objects.get(pk=request.session.get('temp_user_id'))
        document = Document.objects.get(id=doc_id, uploader=user)

        user_password = user.password  # Make sure you securely store it
        if not user_password:
            return HttpResponse("Password required to decrypt the private key", status=403)

# risk log logic
        one_min_ago = timezone.now() - timedelta(minutes=1)
        views = AccessLog.objects.filter(
        user=user,
        document=document,
        action='view',
        timestamp__gte=one_min_ago
            ).count()

        if views >= 5:
            RiskLog.objects.create(
            user=user,
            action='view_document',
            description=f'User viewed document {document.title} 5+ times within 1 minute',
            risk_level='medium',
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        # decrpytion logic
        decrypted_private_key_pem = decrypt_private_key(user.rsa_private_key_encrypted, user_password)
        private_key = serialization.load_pem_private_key(
            decrypted_private_key_pem,
            password=None,
        )


        aes_key = private_key.decrypt(
        document.encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),  
            algorithm=hashes.SHA1(),                
            label=None
        )
)
        
        encrypted_data = document.encrypted_file.read()
        iv = encrypted_data[:12]  
        ciphertext = encrypted_data[12:-16]  
        tag = encrypted_data[-16:]

        decryptor = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(iv, tag)
        ).decryptor()

        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        AccessLog.objects.create(
        user=user,
        document=document,
        action='view',
        ip_address=request.META.get('REMOTE_ADDR'),
        metadata=None
        )
        return FileResponse(io.BytesIO(decrypted_data), as_attachment=True, filename=f"{document.title}.pdf")

    except Exception as e:
         error_details = traceback.format_exc()
         return HttpResponse(f"<h3>Error while decrypting:</h3><pre>{error_details}</pre>", status=500)
    


def delete_document(request, doc_id):
    user = User.objects.get(pk=request.session.get('temp_user_id'))
    document = get_object_or_404(Document, id=doc_id, uploader=user)

    document.is_available = False
    document.save()
    AccessLog.objects.create(
        user=user,
        document=document,
        action='delete',
        ip_address=request.META.get('REMOTE_ADDR'),
        metadata=None
    )
    messages.success(request, "Document marked as deleted.")
    return redirect('uploader_dashboard')


# logic to add watermark
def add_watermark_to_pdf(original_pdf_bytes, watermark_text):
    # Create watermark PDF in memory
    watermark_io = io.BytesIO()
    c = canvas.Canvas(watermark_io, pagesize=letter)
    c.setFont("Helvetica", 40)
    c.setFillGray(0.5, 0.5)
    c.saveState()
    c.translate(300, 250)
    c.rotate(45)
    c.drawCentredString(0, 0, watermark_text)
    c.restoreState()
    c.save()
    watermark_io.seek(0)

    # Read original PDF and watermark
    watermark_reader = PdfReader(watermark_io)
    original_reader = PdfReader(io.BytesIO(original_pdf_bytes))
    output_pdf = PdfWriter()

    watermark_page = watermark_reader.pages[0]

    for page in original_reader.pages:
        page.merge_page(watermark_page)
        output_pdf.add_page(page)

    result_stream = io.BytesIO()
    output_pdf.write(result_stream)
    result_stream.seek(0)
    return result_stream


# reviewer view document view
def reviewer_dowload_document(request, doc_id):

    try:
        reviewer = User.objects.get(pk=request.session.get('temp_user_id'))
        document = Document.objects.get(pk=doc_id)
        shared_entry = SharedKey.objects.get(document=document, shared_with=reviewer)

        
        user_password = reviewer.password
        if not user_password:
            return HttpResponse("Password required to decrypt the private key", status=403)
        print(f'after if')
        # Decrypt reviewer’s private key
        decrypted_private_key_pem = decrypt_private_key(reviewer.rsa_private_key_encrypted, user_password)
        private_key = serialization.load_pem_private_key(decrypted_private_key_pem, password=None)

        # Decrypt AES key
        aes_key = private_key.decrypt(
            shared_entry.encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )

        # Decrypt file
        encrypted_data = document.encrypted_file.read()
        iv = encrypted_data[:12]
        ciphertext = encrypted_data[12:-16]
        tag = encrypted_data[-16:]

        decryptor = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(iv, tag)
        ).decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        
                # Add watermark to decrypted PDF
        watermark_text = f"SECURE - Reviewed by {reviewer.username}"
        watermarked_stream = add_watermark_to_pdf(decrypted_data, watermark_text)

        AccessLog.objects.create(
        user=reviewer,
        document=document,
        action='share',
        ip_address=request.META.get('REMOTE_ADDR'),
        metadata=None
        )

        return FileResponse(watermarked_stream, as_attachment=True, filename=f"{document.title}_reviewed.pdf")

    except Exception as e:
        error_details = traceback.format_exc()
        return HttpResponse(f"<h3>Error:</h3><pre>{error_details}</pre>", status=500)



def accesslog_reviewer_view(request):
    user = User.objects.get(pk=request.session.get('temp_user_id'))
    access_logs = AccessLog.objects.filter(user=user).select_related('document').order_by('-timestamp')

    username = user.username
    content = {
        'user': username,
        'access_logs': access_logs
    }    
    return render(request, 'SecureDocAI/reviewer/accesslog.html', context=content)


def accesslog_admin_view(request):
    logs = AccessLog.objects.select_related('user', 'document').order_by('-timestamp')
    content = {
        'access_logs': logs
    }
    return render(request, 'SecureDocAI/admin/accesslog.html', context=content)


def risk_log_view(request):
    risk_logs = RiskLog.objects.select_related('user').order_by('-timestamp')
    return render(request, 'SecureDocAI/admin/risk.html', {'risk_logs': risk_logs})