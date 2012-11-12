# This is a project done entirely by Chris O'Neil
# The project was done for a "Final Exam" for an online class called
# Udacity CS253: Web Application Engineering

# The project was started and all server code was finished July 2012


import os
import webapp2
import jinja2 # as a template
import hashlib #to make our cookies more secure - see "secure functions"
import hmac #another security function, so we can add a secret to our hash
import cgi
import re #to pick which letters and characters are valid
import json #json library	
from time import gmtime, strftime  #to convert time for my json
strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime())
from google.appengine.api import memcache #importing memory cache
import time

#jinja enviroment, must have this
jinja_environment = jinja2.Environment(autoescape=False,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))

#TEMPLATES
main_template = jinja_environment.get_template('wiki_front.html') #/wiki
user_main_template = jinja_environment.get_template('wiki_page_login.html') #/wiki while logged in
edit_template = jinja_environment.get_template('wiki_page_edit.html') #/_edit 
history_template = jinja_environment.get_template('wiki_history.html') #/_history
#post_template = jinja_environment.get_template('blog_post.html') #/_edit
signup_template = jinja_environment.get_template('blog_login.html') #/wiki/signup
currentuser_template = jinja_environment.get_template('blog_currentuser.html') #/wiki/login
#TEMPLATE VALUES AND OTHER GLOABAL VARIABLES
template_values = {
            'title':'',
            'body': '',
	    'error': ''
        }###############
login_template_values = {
			'username':'',
			'user_error':'',
			'password':'',
			'verify':'',
			'email':'',
			'form_error':''
			} ###############
currentuser_template_values = {
			'username':'',
			'password':'',
			'error':''
			} ###############

#POST_TIME = {}
#SINGLE_POST_TIME = {}

#SECURE COOKIE FUNCTIONS
SECRET = 'jelly4SECRET' #shhhhhhhhhhh
def hash_str(s): #change a string into hmac code with secret value
	return hmac.new(SECRET, s).hexdigest()

def make_cookie(username, password): #put into format string,md5string
	return "%s|%s|%s" % (username, password, hash_str(password))

def check_cookie(h):
    if not h:
	return None
    username = h.split('|')[0]
    password = h.split('|')[1]
    if make_cookie(username, password) == h:
        return True


#LOGIN CHECKS FUNCTIONS
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$") #user specifications
PASS_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$") #password specifications
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$") #email specifications
PAGE_RE = r'(/?(?:[a-zA-Z0-9_-]+/?)*)' #add pages
NUM_RE = r'[0-9]+' #add pages v=?

def valid_username(username):
    return USER_RE.match(username)

def valid_password(password, verify):
    if password == verify:
    	return PASS_RE.match(password)
    else:
	return False

def valid_email(email):
    if email =='':
	return True
    return EMAIL_RE.match(email)

#DATABASE
from google.appengine.ext import db
#DATABASE CLASSES
class User(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    joined = db.DateTimeProperty(auto_now_add = True)

class Page(db.Model):
    link = db.StringProperty(required=True)
    post = db.TextProperty(required=True)
    timestamp = db.DateTimeProperty(auto_now_add = True)
#------------------------------------------------------------------------------------
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
#------------------------------------------------------------------------------------
class Wiki(webapp2.RequestHandler):
    def get(self, key=''):
	base = self.request.url
	title = base.split('/')[-1]
	username = None
	if title != 'wiki':
		url = '/wiki/' + title
		edit_link = '/wiki/_edit/' + title
		history_link = '/wiki/_history/' + title
	else:
		url = '/wiki'
		edit_link = '/wiki/_edit'
		history_link = '/wiki/_history'
		title = 'Welcome to the Wiki'
		body = 'You can log in to edit the wiki'
	cookie = self.request.cookies.get('login')
	if cookie:
		username = cookie.split('|')[0]

	post_id = self.request.get('v')
	if not post_id:
		pageQuery = db.GqlQuery("SELECT * FROM Page WHERE link=:1 ORDER BY timestamp DESC", url)
		text = pageQuery.get()
	else:
		text = Page.get_by_id(int(post_id))
		body = text.post
		title = title.split('?')[0]
		if title == 'wiki':
			history_link = '/wiki/_history'
		else:
			history_link = '/wiki/_history/' + title
		
	
	#lalalallalalalaaaaaaaaaa
	if not text:
		self.redirect('/wiki/_edit/' + title)	
	elif not username:
		body = text.post
		self.response.out.write(main_template.render({'title':title, 'body':body}))
	else:
			
		body = text.post
		self.response.out.write(user_main_template.render({'edit_link':edit_link,
									'history_link':history_link,
									'title':title, 
									'body':body,
									'username':username
										}))
#------------------------------------------------------------------------------------
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
#------------------------------------------------------------------------------------
class Edit(Wiki):
     def get(self, key=''): # all of the data base stuff is here
	cookie = self.request.cookies.get('login')
	if cookie and check_cookie(cookie):
		username = cookie.split('|')[0]
		base = self.request.url
		title = base.split('/')[-1]

		if title.split('?')[0] == '_edit' or title == '/wiki':
			url = '/wiki'
			title = 'Welcome to the Wiki'
			#history_link = '/wiki/_history'

		else:
			url = '/wiki/' + title
			#history_link = '/wiki/_history/' + title

		post_id = self.request.get('v')
		if post_id:
			text = Page.get_by_id(int(post_id))
			body = text.post
			title = title.split('?')[0]

		else:
			pageQuery = db.GqlQuery("SELECT * FROM Page WHERE link=:1 ORDER BY timestamp DESC", url)
			text = pageQuery.get()
			if not text:
				body = ''
			else:
				body = text.post

		#this describes the links that we are making
		if title == 'wiki':
			history_link = '/wiki/_history'
		else:
			history_link = '/wiki/_history/' + title

		back_link = url
		self.response.out.write(edit_template.render({'back_link':back_link,
								'history_link':history_link,
								'title':title,
								'body':body,
								'username':username
								}))
	else:
		self.redirect('/wiki/login')

     def post(self, key=''):
	cookie = self.request.cookies.get('login')
	base = self.request.url
	post_id = self.request.get('v')
	title = base.split('/')[-1]
	if title.split('?')[0] == '_edit':
		url = '/wiki'
		title = 'Welcome to the Wiki'

	elif title != '_edit':
		url = '/wiki/' + title

	else:
		url = '/wiki'
		title = 'Welcome to the Wiki'
	
	body = self.request.get("content")
	if not body:
		body  = ' '
	picked_values = {
			'title':title,
			'body':body,
			'error':''}
	
	if post_id:
		p = Page.get_by_id(int(post_id))
		p.post = body
		p.put()
	
	else:
		p = Page(link=url, post=body)
		p.put()
	#redirect to the home page, this needs to be to a new page
	self.redirect(url)

#------------------------------------------------------------------------------------
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
#------------------------------------------------------------------------------------
class History(Wiki):
     def get(self, key=''):
	cookie = self.request.cookies.get('login')
	if cookie and check_cookie(cookie):
		username = cookie.split('|')[0]
		base = self.request.url
		title = base.split('/')[-1]
		if title != '_history':
			url = '/wiki/' + title
			edit_link = '/wiki/_edit/' + title
			
		else:
			url = '/wiki'
			title = 'Welcome to the Wiki'
			edit_link = '/wiki/_edit'
			
		pageQuery = db.GqlQuery("SELECT * FROM Page WHERE link=:1 ORDER BY timestamp DESC", url)
		text = pageQuery.fetch(limit=20)
		if not text:
			self.redirect('/wiki')
		else:
			text = list(text)
		back_link = url
		#self.response.out.write('hello')
		self.response.out.write(history_template.render({'edit_link':edit_link,
								'back_link':back_link,
								'username':username,
								'title':title,
								'wiki_entries':text
								}))
	else:
		self.redirect('/wiki/login')
#------------------------------------------------------------------------------------
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
#------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
#------------------------------------------------------------------------------------
class WikiSignUp(webapp2.RequestHandler):
     def get(self):
	self.response.out.write(signup_template.render({
			'username':'',
			'user_error':'',
			'password':'',
			'verify':'',
			'email':'',
			'form_error':''
			} ))
     def post(self):
	login_values = login_template_values
	#get parameters to check
	username = (self.request.get("username"))
	password = (self.request.get("password"))
	verify = (self.request.get("verify"))
	email = (self.request.get("email"))

	check_username = valid_username(username)
	login_values['username'] = username #add to template
	check_password = valid_password(password,verify)
	check_email = valid_email(email)
	login_values['email'] = email #add to tempate

	check_user = User.gql("WHERE username = :1", username).get()
	if check_user:
		login_values['user_error'] = 'That user already exists!'
		if not (check_username and check_password and check_email):
			login_values['form_error'] = 'There is an error in the data you submitted.'
		self.response.out.write(login_template.render(login_values))
		
	elif (check_username and check_password and check_email):
		if verify == password:
			new = User(username=username, password=hash_str(password))
			new.put()
			cookie = make_cookie(username, password)			
			self.response.headers.add_header('Set-Cookie', 'login=%s; Path=/' % str(cookie))
			self.redirect('/wiki')
	else:
		login_values['form_error'] = 'There is an error in the data you submitted.'
		self.response.out.write(login_template.render(login_values))
#------------------------------------------------------------------------------------
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
#------------------------------------------------------------------------------------
class WikiLogin(webapp2.RequestHandler):
     def get(self):
	currentuser_values = currentuser_template_values
	self.response.out.write(currentuser_template.render(currentuser_template_values))
     def post(self):
	username = (self.request.get("username"))
	password = (self.request.get("password"))
	h_password = hash_str(password)
	h_check_user = User.gql("WHERE username = :1 and password = :2", username, h_password).get()
	check_user = User.gql("WHERE username = :1 and password = :2", username, password).get()
	if check_user or h_check_user:
		cookie = make_cookie(username, password)			
		self.response.headers.add_header('Set-Cookie', 'login=%s; Path=/' % str(cookie))
		self.redirect('/wiki')
	else:
		self.response.out.write('sorry...')
#------------------------------------------------------------------------------------
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
#------------------------------------------------------------------------------------
class WikiLogout(webapp2.RequestHandler):
     def get(self):
	self.response.headers.add_header('Set-Cookie', 'login=''; Path=/')
	self.redirect('/wiki')

#------------------------------------------------------------------------------------
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
#------------------------------------------------------------------------------------
app = webapp2.WSGIApplication([
                ('/wiki/signup', WikiSignUp),
				('/wiki/login', WikiLogin),
				('/wiki/logout', WikiLogout),
				('/wiki/_edit' + PAGE_RE, Edit),
				('/wiki/_history' + PAGE_RE, History),
				('/wiki'+ PAGE_RE, Wiki)
				],
                              debug=True)
