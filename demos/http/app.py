# -*- coding: utf-8 -*-
"""
    :author: Grey Li (李辉)
    :url: http://greyli.com
    :copyright: © 2018 Grey Li
    :license: MIT, see LICENSE for more details.
"""
import os
# 这里的导入做了兼容性处理。
try:
    from urlparse import urlparse, urljoin
except ImportError:
    from urllib.parse import urlparse, urljoin

from jinja2 import escape
from jinja2.utils import generate_lorem_ipsum
from flask import Flask, make_response, request, redirect, url_for, abort, session, jsonify

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'secret string')


# get name value from query string and cookie
@app.route('/')
@app.route('/hello')
def hello():
    # 先从查询参数中获取name的值，如果没有就从Cookie中寻找
    name = request.args.get('name')
    if name is None:
        name = request.cookies.get('name', 'Human')
    response = '<h1>Hello, %s!</h1>' % escape(name)  # escape name to avoid XSS
    # return different response according to the user's authentication status
    print(len(session.keys()))
    if 'logged_in' in session:
        response += '[Authenticated]'
    else:
        response += '[Not Authenticated]'
    return response


# redirect 重定向
@app.route('/hi')
def hi():
    return redirect(url_for('hello'))


# XSS漏洞演示
@app.route('/hithere')
def hithere():
    name = request.args.get('name')
    response = '<h1>Hello, %s!</h1>' % name
    return response


@app.route('/hithere2')
def hithere2():
    name = request.args.get('name')
    # XSS攻击防范，使用Jinja2提供的escape()函数对用户传入的数据进行转义
    response = '<h1>Hello, %s!</h1>' % escape(name)
    return response


# use int URL converter
@app.route('/goback/<int:year>')
def go_back(year):
    return 'Welcome to %d!' % (2018 - year)


# use any URL converter
@app.route('/colors/<any(blue, white, red):color>')
def three_colors(color):
    return '<p>Love is patient and kind. Love is not jealous or boastful or proud or rude.</p>'


# return error response
@app.route('/brew/<drink>')
def teapot(drink):
    if drink == 'coffee':
        abort(418)
    else:
        return 'A drop of tea.'


# 404
@app.route('/404')
def not_found():
    abort(404)


@app.route('/fooerr')
def fooerr():
    return jsonify(message='Foo Error!'), 500


# return response with different formats
@app.route('/note', defaults={'content_type': 'text'})
@app.route('/note/<content_type>')
def note(content_type):
    content_type = content_type.lower()
    if content_type == 'text':
        body = '''Note
to: Peter
from: Jane
heading: Reminder
body: Don't forget the party!
'''
        response = make_response(body)
        response.mimetype = 'text/plain'
    elif content_type == 'html':
        body = '''<!DOCTYPE html>
<html>
<head></head>
<body>
  <h1>Note</h1>
  <p>to: Peter</p>
  <p>from: Jane</p>
  <p>heading: Reminder</p>
  <p>body: <strong>Don't forget the party!</strong></p>
</body>
</html>
'''
        response = make_response(body)
        response.mimetype = 'text/html'
    elif content_type == 'xml':
        body = '''<?xml version="1.0" encoding="UTF-8"?>
<note>
  <to>Peter</to>
  <from>Jane</from>
  <heading>Reminder</heading>
  <body>Don't forget the party!</body>
</note>
'''
        response = make_response(body)
        response.mimetype = 'application/xml'
    elif content_type == 'json':
        body = {"note": {
            "to": "Peter",
            "from": "Jane",
            "heading": "Remider",
            "body": "Don't forget the party!"
        }
        }
        response = jsonify(body)
        # equal to:
        # response = make_response(json.dumps(body))
        # response.mimetype = "application/json"
    else:
        abort(400)
    return response


# set cookie
@app.route('/set/<name>')
def set_cookie(name):
    response = make_response(redirect(url_for('hello')))
    response.set_cookie('name', name)
    return response


# log in user
@app.route('/login')
def login():
    session['logged_in'] = True
    session['login_name'] = 'who_knows'
    return redirect(url_for('hello'))


# protect view
# 模拟管理后台，只允许登录用户访问
@app.route('/admin')
def admin():
    if 'logged_in' not in session:
        abort(403)
    return 'Welcome to admin page.'


# log out user 模拟退出登录
@app.route('/logout')
def logout():
    if 'logged_in' in session:
        session.pop('logged_in')
    return redirect(url_for('hello'))


# AJAX
@app.route('/post')
def show_post():
    post_body = generate_lorem_ipsum(n=2)
    return '''
<h1>A very long post</h1>
<div class="body">%s</div>
<button id="load">Load More</button>
<script src="https://code.jquery.com/jquery-3.3.1.min.js"></script>
<script type="text/javascript">
$(function() {
    $('#load').click(function() {
        $.ajax({
            url: '/more',
            type: 'get',
            success: function(data){
                $('.body').append(data);
            }
        })
    })
})
</script>''' % post_body


@app.route('/more')
def load_post():
    return generate_lorem_ipsum(n=1)


# redirect to last page
@app.route('/foo')
def foo():
    print(request.full_path)
    print(url_for('do_something', next=request.full_path))
    return '<h1>Foo page</h1><a href="%s">Do something and redirect</a>' \
           % url_for('do_something', next=request.full_path)


@app.route('/bar')
def bar():
    print(request.full_path)
    return '<h1>Bar page</h1><a href="%s">Do something and redirect</a>' \
           % url_for('do_something', next=request.full_path)


@app.route('/do-something')
def do_something():
    # do something here
    return redirect_back()


def is_safe_url(target):
    print("target: ", target)
    print("host_url: ", request.host_url)
    print("urljoin: ", urljoin(request.host_url, target))
    ref_url = urlparse(request.host_url)
    print("ref_url: ", ref_url)
    test_url = urlparse(urljoin(request.host_url, target))
    print("test_url: ", test_url)
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc


def redirect_back(default='hello', **kwargs):
    for target in request.args.get('next'), request.referrer:
        if not target:
            continue
        if is_safe_url(target):
            return redirect(target)
    return redirect(url_for(default, **kwargs))

