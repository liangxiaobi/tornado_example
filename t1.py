'''
Created on 2013-5-21

@author: lion
'''
from tornado.httpclient import AsyncHTTPClient
import os
import tornado.ioloop
import tornado.web

#
class MainHandler(tornado.web.RequestHandler):
    @tornado.web.asynchronous
    def get(self):
        self.write("Hello,world")
        self.finish()
        
class StoryHandler(tornado.web.RequestHandler):
    def get(self, story_id):
        self.write("You requested the story " + story_id)

class TemplateHandler(tornado.web.RequestHandler):
    def get(self):
        items = ["Item 1", "Item 2", "Item 3"]
        self.render("template.html", title="My title", items=items)

class CookieHandler(tornado.web.RequestHandler):
    def get(self):
        if not self.get_cookie("mycookie"):
            self.set_cookie("mycookie", "myvalue")
            self.set_secure_cookie("mysecurecookie", "mysecurecookievalue")
            self.write("Your cookie was not set yet,now set cookie mycookie!")
        else:
            self.write("Your cookie was set: " + self.get_cookie("mycookie")+" securitycookie:"+ self.get_secure_cookie("mysecurecookie"))
                   
class MyFormHandler(tornado.web.RequestHandler):
    def get(self):
        if not self.user_is_logged_in():
            raise tornado.web.HTTPError(403)
        self.write('<html><body><form action="/myform" method="post">'
                   '<input type="text" name="message">'
                   '<input type="submit" value="Submit">'
                   '</form></body></html>')

    def post(self):
        self.set_header("Content-Type", "text/plain")
        self.write("You wrote " + self.get_argument("message"))

class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        user_id = self.get_secure_cookie("user")
        if not user_id: return None
        return self.backend.get_user_by_id(user_id)
    def get_user_locale(self):
        if "locale" not in self.current_user.prefs:
            # Use the Accept-Language header
            return None
        return self.current_user.prefs["locale"]

class UserHandler(BaseHandler):
    def get(self):
        print self.current_user
        if not self.current_user:
            self.redirect("/login")
            return
        name = tornado.escape.xhtml_escape(self.current_user)
        self.write("Hello, " + name)

class LoginHandler(BaseHandler):
    def get(self):
        self.write('<html><body><form action="/login" method="post">'
                   'Name: <input type="text" name="name">'
                   '<input type="submit" value="Sign in">'
                   '</form></body></html>')
    def post(self):
        print self.get_argument("name")
        self.set_secure_cookie("user", self.get_argument("name"))
        self.redirect("/user")

class GoogleHandler(tornado.web.RequestHandler, tornado.auth.GoogleMixin):
    @tornado.web.asynchronous
    def get(self):
        if self.get_argument("openid.mode", None):
            self.get_authenticated_user(self._on_auth)
            return
        self.authenticate_redirect()

    def _on_auth(self, user):
        if not user:
            self.authenticate_redirect()
            return
        # Save the user with, e.g., set_secure_cookie()

settings = {
    "static_path": os.path.join(os.path.dirname(__file__), "static"),
    "cookie_secret": "__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",
    "login_url": "/login",
    "xsrf_cookies": False,
}
        
application = tornado.web.Application([
       (r"/",MainHandler),
       (r"/story/([0-9]+)",StoryHandler),
       (r"/myform",MyFormHandler),
       (r"/template",TemplateHandler),
       (r"/cookie",CookieHandler),
       (r"/static/tornado-0.2.tar.gz", tornado.web.RedirectHandler,dict(url="https://github.com/downloads/facebook/tornado/tornado-0.2.tar.gz")),
       (r"/foo", tornado.web.RedirectHandler, {"url":"/bar", "permanent":False}),
       (r"/user", UserHandler),
       (r"/login", LoginHandler),
       (r"/(apple-touch-icon\.png)", tornado.web.StaticFileHandler,
     dict(path=settings['static_path'])),
       ],**settings)
if __name__ == '__main__':
    #AsyncHTTPClient.configure('tornado.curl_httpclient.CurlAsyncHTTPClient')
    tornado.locale.load_translations(os.path.join(os.path.dirname(__file__), "translations"))
    application.listen(8888)
    tornado.ioloop.IOLoop.instance().start()
    pass