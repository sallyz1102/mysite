from django.shortcuts import render
from django.shortcuts import redirect

from . import models
from . import forms

import hashlib

# Create your views here.
"""
*** 定义hash函数
"""
def hash_code(s, salt='mysite'):
    h = hashlib.sha256()
    s += salt
    h.update(s.encode())
    return h.hexdigest()

"""
*** 显示主页
"""
def index(request):
    if not request.session.get('is_login', None):
        return redirect('/login/')
    return render(request, 'login/index.html')

"""
*** 登录
"""
def login(request):
    if request.session.get('is_login', None):
        return redirect('/index/')
    if request.method == "POST":
        login_form = forms.UserForm(request.POST)
        #username = request.POST.get('username')
        #password = request.POST.get('password')
        message = 'Check your input'
        #if username.strip() and password:
        if login_form.is_valid():
            username = login_form.cleaned_data.get('username')
            password = login_form.cleaned_data.get('password')
            # 验证用户名合法性
            # 验证密码长度
            # 更多其他验证
            try:
                user = models.User.objects.get(name=username)
            except:
                message = "Unexist user"
                #return render(request, 'login/login.html', {'message': message})
                return render(request, 'login/login.html', locals())

            if user.password == hash_code(password):
                request.session['is_login'] = True
                request.session['user_id'] = user.id
                request.session['user_name'] = user.name
                return redirect('/index/')
            else:
                message = 'Incorrect password'
                #return render(request, 'login/login.html', {'message': message})
                return render(request, 'login/login.html', locals())
        else:
            #return render(request, 'login/login.html', {'message':message})
            return render(request, 'login/login.html', locals())

    login_form = forms.UserForm()
    return render(request, 'login/login.html', locals())

"""
*** 注册
"""
def register(request):
    if request.session.get('is_login', None):
        return redirect('/index/')

    if request.method == 'POST':
        register_form = forms.RegisterForm(request.POST)
        message = "Check your input"

        if register_form.is_valid():
            username = register_form.cleaned_data.get('username')
            password1 = register_form.cleaned_data.get('password1')
            password2 = register_form.cleaned_data.get('password2')
            sex = register_form.cleaned_data.get('sex')
            email = register_form.cleaned_data.get('email')

            # 两次输入的密码不同
            if password1 != password2:
                message = "Incorrect passwords input"
                return render(request, 'login/register.html', locals())
            else:
                same_name_user = models.User.objects.filter(name=username)
                if same_name_user:
                    message = "Already registed User Name"
                    return render(request, 'login/register.html', locals())

                same_email_user = models.User.objects.filter(email=email)
                if same_email_user:
                    message = "Already registed Email"
                    return render(request, 'login/register.html', locals())

                new_user = models.User()
                new_user.name = username
                new_user.password = hash_code(password1)
                new_user.sex = sex
                new_user.email = email
                new_user.save()

                return redirect('/login/')
        else:
            return render(request, 'login/register.html', locals())

    register_form = forms.RegisterForm()
    return render(request, 'login/register.html', locals())

"""
*** 退出登录
"""
def logout(request):
    if not request.session.get('is_login', None):
        return redirect('/login/')

    request.session.flush()
    return redirect('/login/')
