from django.http import HttpResponse, HttpRequest
from django.shortcuts import render, redirect
import json
import os
from django.contrib import messages
from rest_framework.decorators import api_view

from djangoProject.settings import MEDIA_ROOT
from rest_framework.response import Response

error = 0


def lk_persona(request):
    context = {
        'new': False
    }
    if request.COOKIES.get('user'):
        username = request.COOKIES['user']
        with open(MEDIA_ROOT + '/data.json') as f:
            templates = json.load(f)
        password = None
        for el in templates:
            if el['username'] == username:
                password = el['password']
        if password == '' or password is None:
            context = {
                'new': True
            }
    return render(request, 'lab1/persona.html', context=context)


def persona(request):
    global error
    if error >= 3:
        messages.error(request, 'Превышено кол-во попыток')
        return render(request, 'lab1/home.html')
    if request.method == 'POST':
        if request.COOKIES.get('user'):
            return redirect('lk_persona')
        username = request.POST.get('username')
        password = request.POST.get('password')
        with open(MEDIA_ROOT + '/data.json') as f:
            templates = json.load(f)
        for user in templates:
            if user['username'] == username:
                if user['locked']:
                    messages.error(request, 'Пользователь заблокирован')
                    return render(request, 'lab1/home.html')
                if user['password'] == password:
                    response = redirect('lk_persona')
                    response.set_cookie(key='user', value=username)
                    return response
                else:
                    error += 1
                    messages.error(request, 'Пароль неверный')
                    return render(request, 'lab1/home.html')
        messages.error(request, 'Пользователя с таким username не существует')
    else:
        if request.COOKIES.get('user'):
            return redirect('lk_persona')
    return render(request, 'lab1/home.html')


def admin_persona(request):
    global error
    if error >= 3:
        messages.error(request, 'Превышено кол-во попыток')
        return render(request, 'lab1/admin.html')
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        with open(MEDIA_ROOT + '/data.json') as f:
            templates = json.load(f)
        for user in templates:
            if user['username'] == username:
                if user['password'] == password:
                    response = redirect('admin_home')
                    response.set_cookie(key='user', value=username)
                    return response
                else:

                    error += 1
                    messages.error(request, 'Пароль неверный')
                    return render(request, 'lab1/admin.html')
        messages.error(request, 'Пользователя с таким username не существует')
    else:
        if request.COOKIES.get('user'):
            if request.COOKIES.get('user') == 'admin':
                return redirect('admin_home')
            else:
                return redirect('lk_persona')
    return render(request, 'lab1/admin.html')


def about(request):
    return render(request, 'lab1/about.html')


def change_password_user(request):
    password = request.POST.get('password')
    password2 = request.POST.get('password2')
    if error >= 3:
        messages.error(request, 'Вы совершили слишком много ошибок')
        return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found'))
    with open(MEDIA_ROOT + '/data.json') as f:
        templates = json.load(f)
    if not request.COOKIES.get('user'):
        return redirect('persona')
    else:
        username = request.COOKIES.get('user')
    for el in templates:
        if el['username'] == username:
            if el.get('num_limit'):
                if len(password) >= int(el.get('num_limit')):
                    if el['password'] == '':
                        el['password'] = password
                        messages.success(request, 'Пароль изменен')
                    elif password2 == el['password']:
                        el['password'] = password
                        messages.success(request, 'Пароль изменен')
                    else:
                        messages.error(request, 'Неверный пароль')
                else:
                    messages.error(request, 'Пароль не соответсвует размеру - {}'.format(int(el.get('num_limit'))))
            else:
                if el['password'] == '':
                    el['password'] = password
                    messages.success(request, 'Пароль изменен')
                elif password2 == el['password']:
                    el['password'] = password
                    messages.success(request, 'Пароль изменен')
                else:
                    messages.error(request, 'Неверный пароль')
    with open(MEDIA_ROOT + '/data.json', 'w') as f:
        json.dump(templates, f)
    return redirect('lk_persona')


def check_user(request):
    username = request.POST.get('username')
    with open(MEDIA_ROOT + '/data.json') as f:
        templates = json.load(f)
    for user in templates:
        if user['username'] == username:
            block = user['block']
            password = user['limit_password']
            return Response(data={
                'block': block,
                'pass': password
            })
    return Response(data={
        'block': False,
        'pass': False
    })


def change_password(request):
    password = request.POST.get('password')
    password2 = request.POST.get('password2')
    with open(MEDIA_ROOT + '/data.json') as f:
        templates = json.load(f)
    with open(MEDIA_ROOT + '/data.json', 'w') as f:
        for el in templates:
            if el['username'] == 'admin':
                if el['password'] == '':
                    if password == password2:
                        el['password'] = password
                        messages.success(request, 'Пароль изменен')
                    else:
                        messages.error(request, 'Пароли не совпадают')
                else:
                    if password2 == el['password']:
                        el['password'] = password
                        messages.success(request, 'Пароль изменен')
                    else:
                        messages.error(request, 'Старый пароль неверный')
        f.seek(0)
        json.dump(templates, f)
    return redirect('admin_home')


def set_user(request):
    user = request.POST.get('user')
    if user == '0':
        messages.error(request, 'Пользователь не выбран')
        return redirect('admin_home')
    action = request.POST.get('action')
    action = int(action)
    if user == '0':
        return redirect('admin_home')
    with open(MEDIA_ROOT + '/data.json') as f:
        templates = json.load(f)
    with open(MEDIA_ROOT + '/data.json', 'w') as f:
        for el in templates:
            if el['username'] == user:
                if action == 1:
                    if el['locked']:
                        el['locked'] = False
                    else:
                        el['locked'] = True
                elif action == 2:
                    limit = request.POST.get('password_limit')
                    el['num_limit'] = int(limit)
                    el['limit_password'] = True
                elif action == 3:
                    el['limit_password'] = False
                    el.pop('num_limit', None)
        f.seek(0)
        json.dump(templates, f)
    return redirect('admin_home')


@api_view(['POST'])
def add_user(request):
    i = 0
    with open(MEDIA_ROOT + '/data.json') as f:
        templates = json.load(f)
        i = len(templates) + 1
        for el in templates:
            if el['username'] == request.POST.get('new_user'):
                return redirect('admin_home')
    with open(MEDIA_ROOT + '/data.json', 'w') as f:
        user = {
            "username": request.POST.get('new_user'),
            "password": '',
            "locked": False,
            "limit_password": False
        }
        templates.append(user)
        f.seek(0)
        json.dump(templates, f)
    return redirect('admin_home')


def admin_home(request):
    users = []
    admin = None
    with open(MEDIA_ROOT + '/data.json') as f:
        templates = json.load(f)
    for user in templates:
        if user.get('num_limit'):
            num_limit = user['num_limit']
        else:
            num_limit = None
        if user['username'] != 'admin':
            users.append({
                "username": user['username'],
                "password": user['password'],
                "locked": user['locked'],
                "limit_password": user['limit_password'],
                "num_limit": num_limit
            })
        else:
            admin = user
    context = {
        'users': users,
        'admin': admin
    }
    return render(request, 'lab1/admin_home.html', context=context)
