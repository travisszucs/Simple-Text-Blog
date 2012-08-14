import os
from string import letters

import webapp2
import jinja2
import random
import string
import hmac
import hashlib

from google.appengine.ext import db

jinja_environment = jinja2.Environment(autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))
    
    
# passwords are created with a random salt, sha256, and hmac
# they are stored in the db under User as 'hash|salt'
def make_salt():
    return ''.join(random.sample(string.letters,5))
    
def make_pw_hash(name, pw, salt):
    if not salt:
            salt = make_salt()
    h = hmac.new(str(salt), name + pw, digestmod=hashlib.sha256).hexdigest()
    return '%s|%s' % (h, salt)
    
def valid_pw(name, pw, h):
    hcheck = make_pw_hash(name, pw, h[1])
    if h[0] == hcheck.split('|')[0]:
        return True
    else:
        return False
      

# basic handler class for other handlers
class Handler(webapp2.RequestHandler):
    
    # writes plain text to the screen
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    
    # used by the render function to get the template
    def render_str(self, template, **params):
        t = jinja_environment.get_template(template)
        return t.render(params)
    
    # renders the template html files
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
   
    # check to see if the user's cookie is valid
    def check_secure_cookie(self, name):
        user_cookie = self.request.cookies.get('userid')
    
        if user_cookie:
            user_cookie = user_cookie.split('|')
            q = User.get_by_id(int(user_cookie[0]))
            if q:
                username = q.username
                pw_hash = q.pw_hash.split('|')
           
                if pw_hash[0] == user_cookie[1]:
                    user_cookie.append(username)
                    return user_cookie
                else:
                    return None
        else:
            return None
    
    # check to see if the viewer is logged in as a user
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        user_cookie = self.check_secure_cookie('userid')
        if user_cookie:
            user_id = user_cookie[0]
            self.user = user_id and User.get_by_id(int(user_id))

        
# db model for posts
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

# db model for users
class User(db.Model):
    username = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty(required = False)
    
    # get db entry by username
    @classmethod
    def get_by_name(cls, username):
        return cls.all().filter('username =', username).get()
    
    # register a new user
    # !!! entry is not stored, must do so by foobar.put() !!!
    @classmethod
    def register(cls, username, pw, email):
        pw_hash = make_pw_hash(username, pw, None)
        return cls(username = username,
                           pw_hash = pw_hash,
                           email = email)
    
    # login the user by checking info provided by them
    @classmethod
    def login(cls, username, pw):
        u = cls.get_by_name(username)
        return u and valid_pw(username, pw, u.pw_hash)
    

    
# handler for /, will display all posts in db
class MainPage(Handler):
    def get(self):
        posts  = db.GqlQuery("SELECT * FROM Post "
                                        "ORDER BY created DESC ")
        self.render("index.html", posts=posts)
    
# handler for /newpost
class NewPost(Handler):
    def get(self):
        self.render("newpost.html")
    
    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        
        if subject and content:
            p = Post(subject = subject, content = content)
            p.put()
            id = p.key().id()
            self.redirect(str(id))
        else:
            error = "post and subject are required!"
            self.render("newpost.html", subject=subject, content=content, error=error)

# handler for permalinks to posts
# permalinks are reached by going to /x
# where x is the post id, the handler will then
# search Post to check if there is a post with the
# same id
class Permalink(Handler):
    def get(self, post_id):
        id = Post.get_by_id(int(post_id))
        
        if id:
            self.render("index.html", posts=[id])
        else:
            self.render("Blog post %s not found!" % id)

# handler for /signup
class Signup(Handler):
    def get(self):
        self.render("signup.html")
        
    def post(self):
        username = self.request.get("username")
        pw = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
        
        
        # usercheck = None means user doesn't already exist
        user_exist = User.get_by_name(username)
        
        if pw == verify and username and not user_exist:
            p = User.register(username, pw, email)
            
            # store info into database since User.register doesn't
            p.put()
           
            # grab user id and make sure hash is sent without salt
            userid = str(p.key().id()) 
            hash = p.pw_hash.split('|')[0]
            
            # set cookie as userid=x|y where x is userid and y is salt
            self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % ('userid', userid + '|' + hash))
            
            self.redirect('/welcome')
            
        else:
            # make sure variables exist to avoid errors
            username_error = ''
            pw_error = ''
                
            if user_exist:
                username_error = "username is already in use!"
            if pw != verify:
                pw_error = "passwords didn't match!"
                
            self.render("signup.html", username = username, email = email,
                                                  username_error = username_error,
                                                  pw_error = pw_error)

# handler for /welcome, which displays "welcome user!"                                             
class Welcome(Handler):
    def get(self):
        user_cookie = self.check_secure_cookie('userid')
            
        if user_cookie:
            self.render("welcome.html", welcome = "welcome " + user_cookie[2] + "!")
        else:
            self.render("welcome.html", welcome = "you haven't logged in!")
            
# handler for /login
class Login(Handler):
    def get(self):
        self.render("login.html")
     
    def post(self):
        username = self.request.get("username")
        pw = self.request.get("password")
        q = User.get_by_name(username)
        
        if username and pw and q:
            # create hash using supplied password + stored salt and
            # check to see if it matches the stored hash
            pw_hash = q.pw_hash.split('|')
            pw_check = valid_pw(username, pw, pw_hash)
        
            if pw_check and username == q.username:
                userid = str(q.key().id()) # grab userid
                self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % ('userid', userid + '|' + str(pw_hash[0])))
                self.redirect('/welcome')
            
        else:
            error = 'invalid login!'
            self.render('login.html', username = username, error = error)
        
class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % ('userid', ''))
        self.redirect('/index')
        
            
app = webapp2.WSGIApplication([
        ('/', MainPage),
        ('/index', MainPage),
        ('/newpost', NewPost),
        ('/(\d+)',  Permalink),
        ('/signup', Signup),
        ('/welcome', Welcome),
        ('/login', Login),
        ('/logout', Logout)],
        debug=True)