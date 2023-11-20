from django.shortcuts import render, redirect
from .forms import UserForm
from .models import User, UserProfile
from django.contrib import messages, auth
from vendor.forms import VendorForm
from .utils import detectUser, send_verification_email
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.exceptions import PermissionDenied
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from vendor.models import Vendor

# Restrict the vendor from accessing the customer page
def check_role_vendor(user):
  if user.role == 1:
    return True

  else:
      raise PermissionDenied

# Restrict the user from accessing the vendor page
def check_role_customer(user):
  if user.role == 2:
    return True

  else:
      raise PermissionDenied


def registerUser(request):
  if request.user.is_authenticated:
    messages.warning(request, 'You are already logged in!')
    return redirect('custDashboard')

  elif request.method == 'POST': # I need to get the request data and create user
    form = UserForm(request.POST)

    if form.is_valid():
      # Create the user using the form
      user = form.save(commit=False)
      password = form.cleaned_data['password']
      user.set_password(password)
      user.role = User.CUSTOMER
      form.save()

      #Email Verification
      mail_subject = "Please activate your account"
      email_template = 'accounts/emails/account_verification.html'
      send_verification_email(request, user, mail_subject, email_template)

      # Create the user using create_user method
      # first_name = form.cleaned_data['first_name']
      # last_name = form.cleaned_data['last_name']
      # username = form.cleaned_data['username']
      # email = form.changed_data['email']
      # password = form.cleaned_data['password']

      # user = User.objects.create_user(first_name=first_name, last_name=last_name, username=username, email=email, password=password)
      # user.role = User.CUSTOMER
      # user.save()

      messages.success(request, 'Your account has been registered successfully! Please verify your email to login!')
      return redirect('login')
    
  else:
    form = UserForm()

  context = {
    'form': form
  }

  return render(request, 'accounts/registerUser.html', context)


def registerVendor(request):

  if request.user.is_authenticated:
    messages.warning(request, 'You are already logged in!')
    return redirect('vendorDashboard')

  elif request.method == "POST":  # Get data and create vendor registration
    form = UserForm(request.POST)
    v_form = VendorForm(request.POST, request.FILES)

    if form.is_valid() and v_form.is_valid():
      # create the restaurant partner profile
      first_name = form.cleaned_data['first_name']
      last_name = form.cleaned_data['last_name']
      username = form.cleaned_data['username']
      email = form.cleaned_data['email']
      password = form.cleaned_data['password']

      user = User.objects.create_user(first_name=first_name, last_name=last_name, username=username, email=email, password=password)
      user.role = User.VENDOR
      user.save() # That create userProfile also because signals

      vendor = v_form.save(commit=False) # commit=False to not save() the vendor yet because i want to set user and user_profile fields on vendor with the user i just created above
      vendor.user = user
      user_profile = UserProfile.objects.get(user=user) # take user-profile to assign it to vendor.user_profile
      vendor.user_profile = user_profile
      vendor.save()

      #Email Verification
      mail_subject = "Please activate your account"
      email_template = 'accounts/emails/account_verification.html'
      send_verification_email(request, user, mail_subject, email_template)


      messages.success(request, 'Your account has been registered successfully! Verify your email address and wait for the approval.')
      return redirect('login')

  else:
    form = UserForm()
    v_form = VendorForm()

  context = {
    'form': form,
    'v_form': v_form
  }

  return render(request, 'accounts/registerVendor.html', context)

def login(request):

  if request.user.is_authenticated:
    messages.warning(request, 'You are already logged in!')
    return redirect('myAccount')

  elif request.method == "POST": # User want to log in 
    email = request.POST['email']#-> this is the name in the input field name='email' and i access it here without name in input field i cannot access here like that
    password = request.POST['password']

    user = auth.authenticate(email=email, password=password)

    if user is not None: # If user has right credentials he will not be None and he will enter his account
      auth.login(request, user)
      messages.success(request, "You are now logged in.")
      return redirect('myAccount')

    else:
      messages.error(request, 'Invalid login credentials')
      return redirect('login')

  return render(request, 'accounts/login.html')

def logout(request):
  if not request.user.is_authenticated:
    messages.error(request, "You are not logged-in to logout!")
    return redirect('login')

  auth.logout(request)
  messages.info(request, "You are logged out")
  return redirect('login')

@login_required(login_url='login')
# Because i need to access myAccount only if i am logged in
def myAccount(request):
  '''
  I have function to detect user in utils.py that give me the dashboard according the user role
  '''
  user = request.user
  redirectUrl = detectUser(user)
  return redirect(redirectUrl)


@login_required(login_url='login')
@user_passes_test(check_role_customer)
def custDashboard(request):
  return render(request, 'accounts/custDashboard.html')


@login_required(login_url='login')
@user_passes_test(check_role_vendor)
def vendorDashboard(request):
  vendor = Vendor.objects.get(user=request.user)
  context = {
    'vendor': vendor
  }
  
  return render(request, 'accounts/vendorDashboard.html', context)


def activate(request, uidb64, token):
  try:
    uid = urlsafe_base64_decode(uidb64).decode()
    user = User._default_manager.get(pk=uid)

  except(TypeError, ValueError, OverflowError, User.DoesNotExist):
    user = None

  if user is not None and default_token_generator.check_token(user, token):
    user.is_active = True
    user.save()
    messages.success(request, "Congratulations! Your account is activated.")
    return redirect('myAccount')

  else:
    messages.error(request, 'Invalid activation link')
    return redirect('myAccount')
  

def forgot_password(request):
  if request.method == "POST":
    email = request.POST['email']

    if User.objects.filter(email=email).exists():
      user = User.objects.get(email__exact=email)

      # Send reset password email to user
      mail_subject = "Reset your Password"
      email_template = 'accounts/emails/reset_password_email.html'
      send_verification_email(request, user, mail_subject, email_template)

      messages.success(request, "Password reset link has been sent to your email address.")
      return redirect('login')
    
    else:
      messages.error(request, "Account with this email address does not exist.")
      return redirect('forgot_password')

  return render(request, 'accounts/forgot_password.html')

def reset_password_validate(request, uidb64, token):
  # Validate the user by decoding the token annd user pk
  try:
    uid = urlsafe_base64_decode(uidb64).decode()
    user = User._default_manager.get(pk=uid)

  except(TypeError, ValueError, OverflowError, User.DoesNotExist):
    user = None

  if user is not None and default_token_generator.check_token(user, token):
    request.session['uid'] = uid
    messages.info(request, 'Please reset your password!')
    return redirect('reset_password')
  
  else:
    messages.error(request, 'This link has been expired!')
    return redirect('myAccount')

def reset_password(request):
  if request.method == "POST":
    password = request.POST['password']
    confirm_password = request.POST['confirm_password']

    if password == confirm_password:
      pk = request.session.get('uid')
      user = User.objects.get(pk=pk)
      user.set_password(password)
      user.is_active = True
      user.save()
      messages.success(request, 'Password reset successfull')
      return redirect('login')

    else:
      messages.error(request, "Passwords do not match!")
      return redirect('reset_password')
    
  return render(request, 'accounts/reset_password.html')