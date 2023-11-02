from django.shortcuts import render, redirect
from .forms import UserForm
from .models import User
from django.contrib import messages
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

      messages.success(request, 'Your account has been registered sucessfully!')
      return redirect('registerUser')
    
    else:
      print(form.errors)
    
  else:
    form = UserForm()

  context = {
    'form': form
  }

  return render(request, 'accounts/registerUser.html', context)
