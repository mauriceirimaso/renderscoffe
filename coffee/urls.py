from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),


    path('signup/', views.signup, name='signup'),
    path('api/login/', views.login, name='login'), 
    path('check_email_availability/', views.check_email_availability, name='check_email_availability'),
    
    path('api/getuserdetails/', views.getuserdetails, name='getuserdetails'),
    path('user/firstfullname/', views.getfirstuserfullname, name='getfirstuserfullname'),
    path('api/user/email/', views.getuseremail, name='getuseremail'),
    
    path('api/getglobalemail/', views.getglobalemailview, name='getglobalemail'),
    path('AllCoffe/', views.getallcoffe, name='getallcoffe'),
    path('api/getproduct/', views.getproductbyid, name='getproductbyid'),
    path('api/latestorder/', views.fetchandincrement, name='fetchlatestorderid'),
    path('api/recordorder/', views.recordorder, name='recordorder'),
    path('api/getallorders/', views.getallorders, name='getallorders'),
    path('api/getallhistory/', views.getallhistory, name='getallhistory'),
    path('api/getorder/', views.getorderbyorderid, name='get_order_by_coffeid'),
    path('api/recordhistory/', views.recordhistory, name='recordhistory'),
    path('api/deleteorder/', views.delete_order, name='delete_order'),
    path('api/gethistory/', views.gethistorybyorderid, name='get_history_by_coffeid'),
    path('api/deletehistory/', views.delete_history, name='delete_history'),
    path('api/recordnotification/', views.recordnotification, name='recordnotification'),
    path('api/notifications/', views.fetch_notifications, name='fetch_notifications'),
    path('api/updatebalance/', views.updatebalance, name='update_balance'),
    path('api/addbalance/', views.addbalance, name='addbalance'),
    path('api/searchcoffee/', views.searchcoffee, name='searchcoffee'),
    path('api/searchhistory/', views.searchhistory, name='searchhistory'),
    path('api/searchorders/', views.searchorders, name='searchorders'),
    path('api/countnotification/', views.countnotification, name='countnotification'),
    path('api/updatenotification/', views.updatenotification, name='updatenotification'),
    path('api/updateorders/', views.updateorders, name='updateorders'),
    path('api/updatehistory/', views.updatehistory, name='updatehistory'),
    path('api/unreadorders/', views.unreadorders, name='unreadorders'),
    path('api/unreadhistory/', views.unreadhistory, name='unreadhistory'),
    path('logout/', views.logout, name='logout'),
    path('isloggedin/',views.isloggedin, name='isloggedin'),
]
