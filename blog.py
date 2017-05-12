import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'fart'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


class MainPage(BlogHandler):
    def get(self):
        self.write('Hello, Udacity!')


# user stuff
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# blog stuff

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author = db.TextProperty(required=True)
    like_count = db.IntegerProperty(required=True)
    like_user = db.ListProperty(str)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

    @property
    def comments(self):
        return Comment.all().filter("postid = ", str(self.key().id()))


class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts=posts)


class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect("/login")

        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user.name
        like_count = 0

        if subject and content:
            p = Post(parent=blog_key(), subject=subject,
                     content=content, author=author, like_count=like_count)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject,
                        content=content, error=error)


# Unit 2 HW's
class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text=rot13)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Unit2Signup(Signup):
    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)


class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')


class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')


class Unit3Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')


class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username=username)
        else:
            self.redirect('/unit2/signup')


# post edit processed here
class Edit(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if not post:
                self.error(404)
                return

            post_author = post.author
            current_user = self.user.name
            if post_author == current_user:
                error = ""
                self.render("edit.html", subject=post.subject,
                            content=post.content, error=error,
                            postkey=post.key())
            else:
                self.redirect("/editerror")
        else:
            self.redirect("/login")

    def post(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post_edit = db.get(key)

            if not post_edit:
                self.error(404)
                return

            post_author = post_edit.author
            current_user = self.user.name
            if post_author == current_user:
                subject = self.request.get('subject')
                content = self.request.get('content')

                if subject and content:
                    post_edit.subject = subject
                    post_edit.content = content
                    post_edit.put()
                    self.redirect('/blog/%s' % str(post_edit.key().id()))
                else:
                    error = "subject and content, please!"
                    self.render("edit.html", subject=subject,
                                content=content, error=error)
            else:
                self.redirect("/editerror")
        else:
            self.redirect("/login")


# post edit error processed here
class EditError(BlogHandler):
    def get(self):
        if self.user:
            error = "only author can edit it."
            self.render("error.html", error=error)
        else:
            self.redirect("/login")


# post delete processed here
class Delete(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if not post:
                self.error(404)
                return

            post_author = post.author
            current_user = self.user.name
            if post_author == current_user:
                post.delete()
                self.render("delete.html")
            else:
                self.redirect("/deleteerror")
        else:
            self.redirect('/login')


# post delete error processed here
class DeleteError(BlogHandler):
    def get(self):
        if self.user:
            error = "only author can delete it."
            self.render("error.html", error=error)
        else:
            self.redirect("/login")


# like processed here
class Like(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if not post:
                self.error(404)
                return

            post_author = post.author
            current_user = self.user.name
            if post_author != current_user:
                if current_user not in post.like_user:
                    post.like_count = post.like_count + 1
                    post.like_user.append(current_user)
                    post.put()
                    post = db.get(key)
                    self.redirect('/blog')
                else:
                    self.redirect("/alreadylikeerror")
            else:
                self.redirect("/likeerror")
        else:
            self.redirect("/login")


# like error processed here
class LikeError(BlogHandler):
    def get(self):
        if self.user:
            error = "post cannot be liked by the autor."
            self.render("error.html", error=error)
        else:
            self.redirect("/login")


# can only like once
class AlreadyLikeError(BlogHandler):
    def get(self):
        if self.user:
            error = "already liked."
            self.render("error.html", error=error)
        else:
            self.redirect("/login")


# unlike processed here
class Unlike(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if not post:
                self.error(404)
                return

            post_author = post.author
            current_user = self.user.name
            if post_author != current_user:
                if current_user in post.like_user:
                    post.like_count = post.like_count - 1
                    post.like_user.remove(current_user)
                    post.put()
                    post = db.get(key)
                    self.redirect('/blog')
                else:
                    self.redirect("/notlikeerror")
            else:
                self.redirect("/unlikeerror")
        else:
            self.redirect("/login")


# unlike error processed here
class UnlikeError(BlogHandler):
    def get(self):
        if self.user:
            error = "post cannot be unliked by the autor."
            self.render("error.html", error=error)
        else:
            self.redirect("/login")


# cannot unlike a post not liked yet
class NotLikeError(BlogHandler):
    def get(self):
        if self.user:
            error = "not liked yet."
            self.render("error.html", error=error)
        else:
            self.redirect("/login")


# comment processed here
class Comment(db.Model):
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author = db.TextProperty(required=True)
    postid = db.StringProperty(required=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", c=self)


# new comment processed here
class NewComment(BlogHandler):
    def get(self, post_id):
        if self.user:
            self.render("newcomment.html")
        else:
            self.redirect("/login")

    def post(self, post_id):
        if not self.user:
            return self.redirect("/login")

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        content = self.request.get('content')
        author = self.user.name
        postid = post_id

        if content:
            c = Comment(parent=blog_key(), content=content,
                        author=author, postid=postid)
            c.put()
            self.redirect('/blog/%s' % str(post_id))
        else:
            error = "comment content, please!"
            self.render("newcomment.html", content=content, error=error)


# comment edit processed here
class CommentEdit(BlogHandler):
    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            comment = db.get(key)

            if not comment:
                self.error(404)
                return

            comment_author = comment.author
            current_user = self.user.name
            if comment_author == current_user:
                error = ""
                self.render("commentedit.html",
                            content=comment.content, error=error)
            else:
                self.redirect("/editerror")
        else:
            self.redirect("/login")

    def post(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            comment_edit = db.get(key)

            if not comment_edit:
                self.error(404)
                return

            comment_author = comment_edit.author
            current_user = self.user.name
            if comment_author == current_user:
                content = self.request.get('content')

                if content:
                    comment_edit.content = content
                    comment_edit.put()
                    self.redirect('/blog/%s' % str(post_id))
                else:
                    error = "comment content, please!"
                    self.render("commentedit.html", content=content,
                                error=error)
            else:
                self.redirect("/editerror")
        else:
            self.redirect("/login")


# comment delete processed here
class CommentDelete(BlogHandler):
    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            comment = db.get(key)

            if not comment:
                self.error(404)
                return

            comment_author = comment.author
            current_user = self.user.name
            if comment_author == current_user:
                comment.delete()
                self.render("delete.html")
            else:
                self.redirect("/deleteerror")
        else:
            self.redirect('/login')

app = webapp2.WSGIApplication([('/', BlogFront),
                               ('/unit2/rot13', Rot13),
                               ('/unit2/signup', Unit2Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),
                               ('/blog/([0-9]+)/edit', Edit),
                               ('/editerror', EditError),
                               ('/blog/([0-9]+)/delete', Delete),
                               ('/deleteerror', DeleteError),
                               ('/blog/([0-9]+)/like', Like),
                               ('/likeerror', LikeError),
                               ('/alreadylikeerror', AlreadyLikeError),
                               ('/blog/([0-9]+)/unlike', Unlike),
                               ('/unlikeerror', UnlikeError),
                               ('/notlikeerror', NotLikeError),
                               ('/blog/([0-9]+)/newcomment', NewComment),
                               ('/blog/([0-9]+)/commentedit/([0-9]+)',
                                   CommentEdit),
                               ('/blog/([0-9]+)/commentdelete/([0-9]+)',
                                   CommentDelete),
                               ],
                              debug=True)
