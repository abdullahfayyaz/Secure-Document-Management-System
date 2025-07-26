from django.db import models
import uuid
from django.utils import timezone

class User(models.Model):
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('uploader', 'Uploader'),
        ('reviewer', 'Reviewer'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128)  # store hashed password

    # MFA via Email OTP
    otp_code = models.CharField(max_length=6, null=True, blank=True)
    otp_created_at = models.DateTimeField(null=True, blank=True)
    is_verified = models.BooleanField(default=False)

    # RSA Keys for Encryption
    rsa_public_key = models.TextField()
    rsa_private_key_encrypted = models.TextField()  # encrypted with AES or password

    # User Role
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    date_joined = models.DateTimeField(default=timezone.now)
    failed_login_attempts = models.IntegerField(default=0)
    lockout_until = models.DateTimeField(null=True, blank=True)
    def __str__(self):
        return self.username
    

class Document(models.Model):
    uploader = models.ForeignKey(User, on_delete=models.CASCADE, related_name='uploaded_documents')
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)

    encrypted_file = models.FileField(upload_to='encrypted/')
    encrypted_aes_key = models.BinaryField()
    encrypted_metadata = models.BinaryField(blank=True, null=True)

    classification = models.CharField(max_length=100)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    # Soft delete flag
    is_available = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.title} ({self.classification})"



class ClassificationResult(models.Model):
    document = models.OneToOneField(Document, on_delete=models.CASCADE, related_name='classification_result')
    detected_keywords = models.JSONField()  # List of relevant keywords
    ai_model_version = models.CharField(max_length=50)
    confidence_score = models.FloatField(default=0.0)

    def __str__(self):
        return f"Classification for {self.document.title}"

class AccessLog(models.Model):
    ACTION_CHOICES = [
        ('upload', 'Upload'),
        ('view', 'View'),
        ('share', 'Share'),
        ('download', 'Download'),
        ('review_request', 'Review Request Sent'),
        ('review_status', 'Review Status Changed'),
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('delete', 'Delete'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    document = models.ForeignKey(Document, on_delete=models.CASCADE, null=True, blank=True)
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    metadata = models.JSONField(null=True, blank=True)  # Optional: details like reason or device info

    def __str__(self):
        return f"{self.user.username} {self.action} {self.document.title if self.document else ''} @ {self.timestamp}"



class ReviewRequest(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('denied', 'Denied'),
    ]

    reviewer = models.ForeignKey(User, on_delete=models.CASCADE, limit_choices_to={'role': 'reviewer'})
    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    requested_at = models.DateTimeField(auto_now_add=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    admin_comment = models.TextField(blank=True, null=True)

    class Meta:
        unique_together = ('reviewer', 'document')  # prevent duplicate requests

    def __str__(self):
        return f"{self.reviewer.username} request on {self.document.title} - {self.status}"


class SharedKey(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    shared_with = models.ForeignKey(User, on_delete=models.CASCADE, limit_choices_to={'role': 'reviewer'})
    encrypted_aes_key = models.BinaryField()  # AES key encrypted with reviewer's RSA public key
    shared_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('document', 'shared_with')


class RiskLog(models.Model):
    RISK_LEVELS = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ]

    user = models.ForeignKey('User', on_delete=models.CASCADE)
    action = models.CharField(max_length=100)  # e.g., 'login', 'upload', 'view_document'
    description = models.TextField()
    risk_level = models.CharField(max_length=10, choices=RISK_LEVELS, default='low')
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.user.username} - {self.action} - {self.risk_level}"