from django.http import HttpResponse, HttpRequest
from django.shortcuts import render, redirect
import json
import os
from django.contrib import messages
from rest_framework.decorators import api_view
from djangoProject.settings import MEDIA_ROOT
from rest_framework.response import Response
from Crypto.Cipher import AES

from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 32  # Bytes
error = 0
key = b'key_admin_encryp'
encrypt_key = True


def encrypt(key_user):
    if key == key_user:
        with open(MEDIA_ROOT + '/data.json', "rb") as f:
            templates = f.read()
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(templates, BLOCK_SIZE))
        with open(MEDIA_ROOT + '/data2.json', "wb") as f:
            f.write(ciphertext)
        return True
    else:
        return False


# encrypt(b'key_admin_encryp')


@api_view(['GET'])
def exit_program(request):
    encrypt(b'key_admin_encryp')
    os.remove('E:\\Лабы по новым технологиям\\djangoProject\\media\\data.json')
    return render(request, 'lab1/exit.html')


def decipher(key_user):
    if key == key_user:
        with open(MEDIA_ROOT + '/data2.json', "rb") as f:
            templates = f.read()
        decipher = AES.new(key, AES.MODE_ECB)
        msg_dec = unpad(decipher.decrypt(templates), BLOCK_SIZE)
        # msg_dec = str(msg_dec).split(']')[0] + ']'
        # msg_dec = msg_dec.encode('utf-8')
        # msg_dec = json.loads(msg_dec)
        with open(MEDIA_ROOT + '/data.json', 'wb') as f:
            f.write(msg_dec)
        return True
    else:
        return False


def change_forms(request):
    return render(request, 'lab1/forms.html')


def change_encrypt(request):
    global encrypt_key, error
    if request.method == 'POST':
        password = request.POST.get('password')
        if password.encode('utf-8') == key:
            encrypt_key = False
            messages.success(request, 'ok')
            decipher(key)
        else:
            error = 100
            messages.error(request, 'Ошибка пароля')
    else:
        messages.error(request, 'Ошибка пароля')
    return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found'))


def login_user_admin(request):
    global error
    if error >= 3:
        messages.error(request, 'Превышено кол-во попыток')
        return render(request, 'lab1/home.html')
    if encrypt_key:
        return render(request, 'lab1/encrypt.html')
    user = request.COOKIES.get('user')
    auth = request.COOKIES.get('auth')
    if auth is not None:
        auth = int(auth)
    if request.method == 'POST':
        if user:
            if auth == 0 or auth is None:
                response = render(request, 'lab1/forms.html')
                return response
            if user == 'admin':
                return redirect('admin_home')
            else:
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
                if user['password'] == '':
                    response = render(request, 'lab1/forms.html')
                    response.set_cookie(key='user', value=username)
                    response.set_cookie(key='auth', value=0)
                    return response
                if user['password'] == password:
                    if user['username'] == 'admin':
                        response = redirect('admin_home')
                        response.set_cookie(key='user', value=username)
                        response.set_cookie(key='auth', value=1)
                        return response
                    response = redirect('lk_persona')
                    response.set_cookie(key='user', value=username)
                    response.set_cookie(key='auth', value=1)
                    return response
                else:
                    error += 1
                    messages.error(request, 'Пароль неверный')
                    return render(request, 'lab1/home.html')
        messages.error(request, 'Пользователя с таким username не существует')
    else:
        if user:
            if auth == 0 or auth is None:
                return render(request, 'lab1/forms.html')
            if user == 'admin' and auth == 1:
                return redirect('admin_home')
            if auth == 1:
                return redirect('lk_persona')
    return render(request, 'lab1/home.html')


def lk_persona(request):
    context = {
        'new': False
    }
    if request.COOKIES.get('user') and request.COOKIES.get('user') == 1:
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
    response = None
    for el in templates:
        if el['username'] == username:
            if el.get('num_limit'):
                if len(password) >= int(el.get('num_limit')):
                    if el['password'] == '':
                        if password == password2:
                            el['password'] = password
                            messages.success(request, 'Пароль изменен')
                            if username == 'admin':
                                response = redirect('admin_home')
                            else:
                                response = redirect('lk_persona')
                            response.set_cookie(key='auth', value=1)
                            return response
                        else:
                            messages.error(request, 'Пароли не совпадают')
                            return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found'))
                    elif password2 == el['password']:
                        el['password'] = password
                        messages.success(request, 'Пароль изменен')
                        if username == 'admin':
                            response = redirect('admin_home')
                        else:
                            response = redirect('lk_persona')
                        response.set_cookie(key='auth', value=1)
                    else:
                        messages.error(request, 'Неверный пароль')
                        return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found'))
                else:
                    messages.error(request, 'Пароль не соответсвует размеру - {}'.format(int(el.get('num_limit'))))
                    return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found'))
            else:
                if el['password'] == '':
                    if password == password2:
                        el['password'] = password
                        messages.success(request, 'Пароль изменен')
                        if username == 'admin':
                            response = redirect('admin_home')
                        else:
                            response = redirect('lk_persona')
                        response.set_cookie(key='auth', value=1)
                    else:
                        messages.error(request, 'Пароли не совпадают')
                        return render(request, 'lab1/forms.html')
                elif password2 == el['password']:
                    el['password'] = password
                    messages.success(request, 'Пароль изменен')
                    if username == 'admin':
                        response = redirect('admin_home')
                    else:
                        response = redirect('lk_persona')
                    response.set_cookie(key='auth', value=1)
                else:
                    messages.error(request, 'Неверный пароль')
                    return redirect(request.META.get('HTTP_REFERER', 'redirect_if_referer_not_found'))
    with open(MEDIA_ROOT + '/data.json', 'w') as f:
        json.dump(templates, f)
    if response is not None:
        return response
    if username == 'admin':
        return redirect('admin_home')
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
    a = request.COOKIES.get('user')
    b = request.COOKIES.get('auth')
    if request.COOKIES.get('user') is not None and request.COOKIES.get('auth') == str(1):
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
    return redirect('persona')
