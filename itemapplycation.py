from flask import Flask, render_template, request, redirect,jsonify, url_for, flash

from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import *

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"

#Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Flask Routing
# Homepage
@app.route('/')
@app.route('/index/')
def displayCatalog():
    categories = session.query(Category).order_by(asc(Category.name))
    items = session.query(Items).order_by(desc(Items.date)).limit(5)
    return render_template('index.html', categories = categories, items = items)

# Category Items from catalogdb
@app.route('/index/<path:category_name>/items/')
def displayCategory(category_name):
    categories = session.query(Category).order_by(asc(Category.name))
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Items).filter_by(category=category).order_by(asc(Items.name)).all()
    count = session.query(Items).filter_by(category=category).count()
    created_by = getUserInfo(category.user_id)
    if 'username' not in login_session or created_by.id != login_session['user_id']:
        return render_template('public_items.html', category = category.name,
                               categories = categories, items = items, count = count
                               )
    else:
        user = getUserInfo(login_session['user_id'])
        return render_template('items.html', category = category.name, categories = categories,
                               items = items, count = count, user=user
                               )

# Display a Specific Item from db
@app.route('/index/<path:category_name>/<path:item_name>/')
def displayItem(category_name, item_name):
    item = session.query(Items).filter_by(name=item_name).one()
    created_by = getUserInfo(item.user_id)
    categories = session.query(Category).order_by(asc(Category.name))
    if 'username' not in login_session or created_by.id != login_session['user_id']:
        return render_template('public_item_detail.html', item = item, category = category_name,
                               categories = categories, created_by = created_by
                               )
    else:
        return render_template('item_detail.html', item = item, category = category_name,
                               categories = categories, created_by = created_by
                               )

# Utilities functions
def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user

# JSON
@app.route('/index/JSON')
def itemsJSON():
    categories = session.query(Category).all()
    category_dict = [c.serialize for c in categories]
    for c in range(len(category_dict)):
        items = [i.serialize for i in session.query(Items)\
                    .filter_by(category_id=category_dict[c]["id"]).all()]
        if items:
            category_dict[c]["Item"] = items
    return jsonify(Category=category_dict)

@app.route('/catalog/categories/JSON')
def categoriesJSON():
    categories = session.query(Category).all()
    return jsonify(categories=[c.serialize for c in categories])

if __name__ == '__main__':
    app.secret_key = "secret_key"
    app.debug = True
    app.run(host = '0.0.0.0', port = 5000)
