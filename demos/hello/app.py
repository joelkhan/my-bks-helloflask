# -*- coding: utf-8 -*-
"""
    :author: Grey Li (李辉)
    :url: http://greyli.com
    :copyright: © 2018 Grey Li
    :license: MIT, see LICENSE for more details.
"""
import click
from flask import Flask

app = Flask(__name__)


# the minimal Flask application
@app.route('/')
def index():
    return '<h1>Hello, World!</h1>'


# bind multiple URL for one view function
# 绑定多个URL到同一视图函数
@app.route('/hi')
@app.route('/hello')
def say_hello():
    return '<h1>Hello, Flask!</h1>'


# dynamic route, URL variable default
# 使用defaults参数设置URL变量的默认值
@app.route('/greet', defaults={'name': 'Programmer'})
@app.route('/greet/<name>')
def greet(name):
    return '<h1>Hello, %s!</h1>' % name


# custom flask cli command
# 创建一个自定义的命令函数
@app.cli.command()
def hello():
    """
    Just say hello.
    就是打个招呼啦~
    """
    click.echo('Hello, Human!')
