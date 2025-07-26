from django.urls import path
from .views import *

urlpatterns = [
    path('', home_view, name="home"),
    path('SignUp/', signup_view, name='signup'),
    path('SignUp/MFA-Verification/', otp_verification, name= 'mfa_verification'),
    path('SignUp/MFA-Verification/Successfully-SignUp', view_success, name= 'mfa_verification_success'),
    path('logout/', logout_view, name="logout"),
    path('Dashboard/', dashboard_view, name="dashboard"),
    path('Dashboard/Admin/', admin_deashboard_view, name="admin_dashboard"),
    path('Dashboard/Uploader/', uploader_dashboard_view, name="uploader_dashboard"),
    path('Dashboard/Uploader/View_Document/', uploader_viewdocument_view, name="uploaderViewDocument"),
    path('Dashboard/Uploader/Accesslog/', uploader_accesslog_view, name="uploaderAccesslog"),
    path('Dashboard/Reviewer/', reviewer_dashboard_view, name="reviewer_dashboard"),
    path('Dashboard/Admin/', admin_deashboard_view, name="admin_dashboard"),
    path('Dashboard/Admin/RequestDocument/', admin_DocReq_view, name="admin_Doc"),
    path('Dashboard/Admin/Requests/', admin_Request_view, name="admin_Requests"),
    path('Dashboard/Admin/Access_logs/', accesslog_admin_view, name="admin_accesslog"),
    path('Dashboard/Admin/Risk-Check/', risk_log_view, name="admin_risk"),
    path("update-review-status/", update_review_status, name="update_review_status"),
    path('Dashboard/Admin/users/', admin_users_view, name="admin_users"),
    path('document/view/<int:doc_id>/', reviewer_dowload_document, name='reviewer_download'),
    path('request-access/<int:document_id>/', reviewer_snd_request_view, name='request_access'),
    path('Dashboard/Reviewer/My_Document/', reviewer_my_doc_view, name="reviewer_dashboard_myDoc"),
    path('Dashboard/Reviewer/Access_log/', accesslog_reviewer_view, name="reviewer_accesslog"),
    path('Dashboard/Reviewer/Request_Access/', reviewer_request_view, name="reviewer_dashboard_Request"),
    path('Dashboard/Uploader/document/view/<int:doc_id>/', view_document1, name='view_document1'),
    path('Dashboard/Uploader/document/delete/<int:doc_id>/', delete_document, name='delete_document'),   

]