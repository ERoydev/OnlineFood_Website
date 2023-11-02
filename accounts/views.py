from django.shortcuts import render, redirect
from .forms import UserForm
from .models import User, UserProfile
from django.contrib import messages
from vendor.form import VendorForm
# Create your views here.


def registerUser(request):
  form = None

  if request.method == 'POST':
    form = UserForm(request.POST)

    if form.is_valid():
      # Create the user using the form
      user = form.save(commit=False)
      password = form.cleaned_data['password']
      user.set_password(password)
      user.role = User.CUSTOMER
      form.save()

      # Create the user using create_user method
      # first_name = form.cleaned_data['first_name']
      # last_name = form.cleaned_data['last_name']
      # username = form.cleaned_data['username']
      # email = form.changed_data['email']
      # password = form.cleaned_data['password']

      # user = User.objects.create_user(first_name=first_name, last_name=last_name, username=username, email=email, password=password)
      # user.role = User.CUSTOMER
      # user.save()
  
      messages.success(request, 'Your account has been registered successfully!')
      return redirect('registerUser')
    
  else:
    form = UserForm()

  context = {
    'form': form
  }

  return render(request, 'accounts/registerUser.html', context)


def registerVendor(request):

  if request.method == "POST":
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
      messages.success(request, 'Your account has been registered successfully! Please wait for the approval.')
      
      return redirect('registerVendor')

  else:
    form = UserForm()
    v_form = VendorForm()

  context = {
    'form': form,
    'v_form': v_form
  }

  return render(request, 'accounts/registerVendor.html', context)